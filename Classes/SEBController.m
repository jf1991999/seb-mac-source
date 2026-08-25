//
//  SEBController.m
//  Safe Exam Browser
//
//  Created by Daniel R. Schneider on 29.04.10.
//  Copyright (c) 2010-2025 Daniel R. Schneider, ETH Zurich, IT Services,
//  based on the original idea of Safe Exam Browser 
//  by Stefan Schneider, University of Giessen
//  Project concept: Thomas Piendl, Daniel R. Schneider, 
//  Dirk Bauer, Kai Reuter, Tobias Halbherr, Karsten Burger, Marco Lehre, 
//  Brigitte Schmucki, Oliver Rahs. French localization: Nicolas Dunand
//
//  ``The contents of this file are subject to the Mozilla Public License
//  Version 2.0 (the "License"); you may not use this file except in
//  compliance with the License. You may obtain a copy of the License at
//  http://www.mozilla.org/MPL/
//  
//  Software distributed under the License is distributed on an "AS IS"
//  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//  License for the specific language governing rights and limitations
//  under the License.
//  
//  The Original Code is Safe Exam Browser for Mac OS X.
//  
//  The Initial Developer of the Original Code is Daniel R. Schneider.
//  Portions created by Daniel R. Schneider are Copyright 
//  (c) 2010-2025 Daniel R. Schneider, ETH Zurich, IT Services,
//  based on the original idea of Safe Exam Browser
//  by Stefan Schneider, University of Giessen. All Rights Reserved.
//  
//  Contributor(s): ______________________________________.
//

#include <Carbon/Carbon.h>
#import "SEBController.h"

// Fix 2 (OFFLINE_RETRY_DEAD_END_PLAN §4): NWPathMonitor is the fast wake source for the
// unattended lock-page retry. Autolinked via modules (CLANG_ENABLE_MODULES=YES) — no
// project.pbxproj change; `otool -L` on the built binary shows Network.framework.
#import <Network/Network.h>
#import <IOKit/pwr_mgt/IOPMLib.h>
#import <IOKit/IOKitLib.h>
#import <ServiceManagement/ServiceManagement.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <mach/mach_init.h>

#import <CommonCrypto/CommonHMAC.h>     // [R6] offline-exit proof (HMAC-SHA256)
#import <CommonCrypto/CommonDigest.h>   // [P2R1 F5] the shared compare (SHA-256 of the normalised code)
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

#import <objc/runtime.h>

#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libproc.h>
#include <assert.h>
#include <sys/sysctl.h>
#include <CoreGraphics/CGDirectDisplay.h>
#import "CGSPrivate.h"

#import "PrefsBrowserViewController.h"
#import "SEBBrowserController.h"
#import "SEBBrowserWindow.h"   // P1 Bug-A: typed blinkeredContentHeld gate (not fail-open KVC)
#import "SEBURLFilter.h"

#import "RNDecryptor.h"
#import "SEBKeychainManager.h"
#import "SEBCryptor.h"
#import "SEBCertServices.h"
#import "NSData+NSDataZIPExtension.h"
#import "NSScreen+SEBScreen.h"
#import "NSWindow+SEBWindow.h"
#import "SEBConfigFileManager.h"
#import "NSRunningApplication+SEB.h"
#import "ProcessManager.h"

#import "SEBDockItemMenu.h"
#import "SEBGoToDockButton.h"

#import "SEBWindowSizeValueTransformer.h"
#import "BoolValueTransformer.h"
#import "IsEmptyCollectionValueTransformer.h"
#import "NSTextFieldNilToEmptyStringTransformer.h"

#include <SystemConfiguration/SystemConfiguration.h>

#import "SEBUIUserDefaultsController.h"
#import <Sparkle/Sparkle.h>


@interface NSArray (ProcessArray)

- (NSArray *)containsProcessObject: (NSString *)processName;

@end

@implementation NSArray (ProcessArray)

// Matches the `name ==[cd] %@` NSPredicate this used to build: case- AND diacritic-insensitive
// equality against each element's `name`, read by KVC exactly as the predicate did.
//
// WHY THIS IS A PLAIN LOOP NOW. The predicate version was the single hottest thing in the app.
// `windowWatcher` fires 4x a second and calls this SIX times per tick; each call parsed a format
// string into a fresh NSPredicate and then evaluated it per element, and predicate evaluation
// resolves the `name` key path through the ObjC runtime every time — a `sample` of a locked
// session put essentially the whole main-thread timer budget inside
// NSFunctionExpression -> class_getInstanceMethod -> lookUpImpOrForward. Roughly 30-50% CPU,
// sustained, on an idle locked Mac, which is what tripped the OS CPU limit and generated
// cpu_resource.diag reports.
//
// The TICK RATE IS DELIBERATELY UNCHANGED. 0.25s is how fast a prohibited window or a screen-sharing
// agent gets noticed, so slowing the watcher down would trade CPU for enforcement latency. The fix
// is to make each tick cheap, not to run it less often.
+ (BOOL)blinkeredProcessName:(NSString *)name matches:(NSString *)processName
{
    if (name == nil || processName == nil) {
        return NO;
    }
    // NSOrderedSame under both options is precisely what ==[cd] tested. Length is NOT used as a
    // fast path: diacritic-insensitive equality can hold across differing lengths (composed vs
    // decomposed forms), so a length guard would silently narrow the match.
    return [name compare:processName
                 options:NSCaseInsensitiveSearch | NSDiacriticInsensitiveSearch] == NSOrderedSame;
}

- (NSArray *)containsProcessObject: (NSString *)processName
{
    NSMutableArray *foundProcesses = nil;
    for (id process in self) {
        NSString *name = [process valueForKey:@"name"];
        if (![name isKindOfClass:[NSString class]]) {
            continue;
        }
        if ([NSArray blinkeredProcessName:name matches:processName]) {
            if (foundProcesses == nil) {
                foundProcesses = [NSMutableArray new];
            }
            [foundProcesses addObject:process];
        }
    }
    // Unchanged contract: nil (not an empty array) when nothing matched — callers test for nil.
    return foundProcesses;
}

@end


io_connect_t  root_port; // a reference to the Root Power Domain IOService

void MySleepCallBack(void * refCon, io_service_t service, natural_t messageType, void * messageArgument);
bool insideMatrix(void);


#pragma mark - Blinkered guided onboarding (first-run permission setup)

static NSTextField *BlinkeredMakeLabel(NSString *text, CGFloat size, NSFontWeight weight, NSColor *color, NSRect frame, NSTextAlignment align) {
    NSTextField *l = [[NSTextField alloc] initWithFrame:frame];
    l.stringValue = text ?: @"";
    l.editable = NO; l.bordered = NO; l.drawsBackground = NO; l.selectable = NO;
    l.font = [NSFont systemFontOfSize:size weight:weight];
    l.textColor = color;
    l.alignment = align;
    l.lineBreakMode = NSLineBreakByWordWrapping;
    [l.cell setWraps:YES];
    return l;
}

// A friendly first-run window that walks the user through granting Accessibility (the one
// permission Blinkered needs). Deep-links to the exact System Settings pane and polls
// AXIsProcessTrusted() so it flips to "✓ Enabled" and unlocks Continue automatically.
@interface BlinkeredOnboardingController : NSWindowController <NSWindowDelegate>
@property (nonatomic, strong) NSTimer *pollTimer;
@property (nonatomic, strong) NSTextField *statusPill;
@property (nonatomic, strong) NSButton *openSettingsButton;
@property (nonatomic, strong) NSButton *continueButton;
@property (nonatomic, strong) NSTextField *liveStatus;
@property (nonatomic, copy) void (^onFinish)(void);
@property (nonatomic) BOOL finished;
@property (nonatomic) BOOL wasGranted;
@end

@implementation BlinkeredOnboardingController

- (instancetype)init {
    NSWindow *win = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 560, 600)
        styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskFullSizeContentView)
        backing:NSBackingStoreBuffered defer:NO];
    win.titlebarAppearsTransparent = YES;
    win.titleVisibility = NSWindowTitleHidden;
    win.movableByWindowBackground = YES;
    // Normal level (NOT floating): a floating window sits on top of System Settings and
    // blocks the user from reaching the Accessibility toggle. We instead step aside when
    // Settings opens and pop back to the front the moment permission is granted.
    win.level = NSNormalWindowLevel;
    self = [super initWithWindow:win];
    if (self) { win.delegate = self; [self buildUI]; }
    return self;
}

- (void)buildUI {
    NSView *c = self.window.contentView;
    c.wantsLayer = YES;
    CGFloat W = 560, H = 600;

    NSImageView *icon = [[NSImageView alloc] initWithFrame:NSMakeRect((W-80)/2, H-128, 80, 80)];
    icon.image = [NSApp applicationIconImage];
    icon.imageScaling = NSImageScaleProportionallyUpOrDown;
    [c addSubview:icon];

    [c addSubview:BlinkeredMakeLabel(@"Welcome to Blinkered", 24, NSFontWeightBold, [NSColor labelColor], NSMakeRect(40, H-172, W-80, 32), NSTextAlignmentCenter)];
    [c addSubview:BlinkeredMakeLabel(@"Just one quick permission and you're ready to go.", 13, NSFontWeightRegular, [NSColor secondaryLabelColor], NSMakeRect(40, H-198, W-80, 20), NSTextAlignmentCenter)];

    NSView *card = [[NSView alloc] initWithFrame:NSMakeRect(40, 180, W-80, 205)];
    card.wantsLayer = YES;
    card.layer.backgroundColor = [NSColor colorWithCalibratedWhite:0.5 alpha:0.08].CGColor;
    card.layer.cornerRadius = 14;
    card.layer.borderWidth = 1;
    card.layer.borderColor = [[NSColor separatorColor] colorWithAlphaComponent:0.6].CGColor;
    [c addSubview:card];
    CGFloat CW = card.frame.size.width;

    [card addSubview:BlinkeredMakeLabel(@"Accessibility access", 16, NSFontWeightSemibold, [NSColor labelColor], NSMakeRect(22, 161, 260, 22), NSTextAlignmentLeft)];
    self.statusPill = BlinkeredMakeLabel(@"● Needed", 12, NSFontWeightSemibold, [NSColor systemOrangeColor], NSMakeRect(CW-22-150, 162, 150, 20), NSTextAlignmentRight);
    [card addSubview:self.statusPill];

    // 3-step instructions — explicit so first-time users know exactly what they're about to do
    // when macOS pops the system dialog (which mentions "control this computer" — alarming
    // without context).
    [card addSubview:BlinkeredMakeLabel(
        @"Click the blue button below, then in macOS:",
        12.5, NSFontWeightRegular, [NSColor secondaryLabelColor],
        NSMakeRect(22, 124, CW-44, 18), NSTextAlignmentLeft)];
    [card addSubview:BlinkeredMakeLabel(
        @"1.  Click Open System Settings",
        12, NSFontWeightRegular, [NSColor secondaryLabelColor],
        NSMakeRect(22, 105, CW-44, 16), NSTextAlignmentLeft)];
    [card addSubview:BlinkeredMakeLabel(
        @"2.  Switch the Blinkered toggle on",
        12, NSFontWeightRegular, [NSColor secondaryLabelColor],
        NSMakeRect(22, 88, CW-44, 16), NSTextAlignmentLeft)];
    [card addSubview:BlinkeredMakeLabel(
        @"3.  Enter your Mac password to confirm",
        12, NSFontWeightRegular, [NSColor secondaryLabelColor],
        NSMakeRect(22, 71, CW-44, 16), NSTextAlignmentLeft)];

    // Big visually-dominant primary action — it's the ONLY thing the user
    // needs to click. Full-width inside the card, tall, default button style
    // so it has the blue ring + Enter-to-fire.
    self.openSettingsButton = [[NSButton alloc] initWithFrame:NSMakeRect(22, 22, CW-44, 38)];
    self.openSettingsButton.title = @"Enable Accessibility…";
    self.openSettingsButton.bezelStyle = NSBezelStyleRounded;
    self.openSettingsButton.controlSize = NSControlSizeLarge;
    self.openSettingsButton.keyEquivalent = @"\r";   // default action — Enter triggers it
    self.openSettingsButton.font = [NSFont systemFontOfSize:14 weight:NSFontWeightSemibold];
    self.openSettingsButton.target = self;
    self.openSettingsButton.action = @selector(openSettings:);
    [card addSubview:self.openSettingsButton];

    // Fallback for the rare case where the system prompt doesn't appear.
    NSButton *manualLink = [[NSButton alloc] initWithFrame:NSMakeRect(20, 0, 280, 16)];
    manualLink.title = @"Settings didn't open? Open it manually";
    manualLink.bordered = NO;
    manualLink.font = [NSFont systemFontOfSize:10.5];
    manualLink.contentTintColor = [NSColor secondaryLabelColor];
    manualLink.target = self;
    manualLink.action = @selector(openSettingsManually:);
    [card addSubview:manualLink];

    // Big, prominent live-status line: dark grey while waiting, large bright
    // green when granted. Centred between the card and Continue button so
    // the user can't miss the "ready" moment after returning from Settings.
    self.liveStatus = BlinkeredMakeLabel(@"Waiting for you to enable it…",
        14, NSFontWeightSemibold, [NSColor secondaryLabelColor],
        NSMakeRect(40, 138, W-80, 26), NSTextAlignmentCenter);
    [c addSubview:self.liveStatus];

    self.continueButton = [[NSButton alloc] initWithFrame:NSMakeRect((W-220)/2, 60, 220, 38)];
    self.continueButton.title = @"Continue";
    self.continueButton.bezelStyle = NSBezelStyleRounded;
    self.continueButton.controlSize = NSControlSizeLarge;
    self.continueButton.target = self;
    self.continueButton.action = @selector(finishTapped:);
    self.continueButton.enabled = NO;
    [c addSubview:self.continueButton];

    // No "I'll do this later" — Accessibility is required for the lock to
    // work at all. Letting the user skip it just routes them to a broken
    // experience (silent locks). They can quit the app to skip; nothing
    // else is acceptable.

    [self refreshState];
}

- (void)showOnboarding {
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [self.pollTimer invalidate];
    __weak typeof(self) ws = self;
    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t) { [ws refreshState]; }];
}

- (void)refreshState {
    BOOL granted = AXIsProcessTrusted();
    if (granted) {
        self.statusPill.stringValue = @"✓ Enabled";
        self.statusPill.textColor = [NSColor systemGreenColor];
        // Big, prominent success message — user just returned from Settings
        // and needs to see clearly that the install worked + that they
        // should click Continue. Bigger font + heavier weight + bright
        // green make this the most visible thing on the screen.
        self.liveStatus.stringValue = @"✓ All set — you're ready to go!";
        self.liveStatus.font = [NSFont systemFontOfSize:18 weight:NSFontWeightBold];
        self.liveStatus.textColor = [NSColor systemGreenColor];
        self.openSettingsButton.enabled = NO;
        // Continue is now the only primary action — promote it to default
        // (Enter triggers) since Enable Accessibility is done.
        self.continueButton.keyEquivalent = @"\r";
        self.continueButton.enabled = YES;
        // Just got granted — close System Settings (it was only opened to grant this, and
        // would otherwise sit open behind Blinkered) and surface this window so the user sees
        // the ✓ and the Continue button right away.
        if (!self.wasGranted) {
            self.wasGranted = YES;
            [self closeSystemSettings];
            // Restore from the tucked-aside floating state back to a normal, centred window.
            self.window.level = NSNormalWindowLevel;
            [self.window center];
            [self.window makeKeyAndOrderFront:nil];
            [NSApp activateIgnoringOtherApps:YES];
            [self.window makeFirstResponder:self.continueButton];
        }
    } else {
        self.wasGranted = NO;
        self.statusPill.stringValue = @"● Needed";
        self.statusPill.textColor = [NSColor systemOrangeColor];
        self.liveStatus.stringValue = @"Waiting for you to enable it…";
        self.liveStatus.font = [NSFont systemFontOfSize:14 weight:NSFontWeightSemibold];
        self.liveStatus.textColor = [NSColor secondaryLabelColor];
        self.openSettingsButton.enabled = YES;
        // Enable Accessibility is the default action until the user
        // grants — Enter fires it.
        self.openSettingsButton.keyEquivalent = @"\r";
        self.continueButton.keyEquivalent = @"";
        self.continueButton.enabled = NO;
    }
}

- (void)openSettings:(id)sender {
    // Show macOS's own Accessibility prompt. This both registers Blinkered in the Accessibility
    // list AND presents the system "Open System Settings / Deny" dialog. We deliberately do NOT
    // also deep-link to the pane ourselves: if we did, the user would grant via the pane and
    // macOS's dialog would be left orphaned on screen — and apps are not permitted to close a
    // system security dialog. Letting the dialog's own "Open System Settings" button open the
    // pane means it dismisses itself cleanly when the user acts on it.
    NSDictionary *opts = @{(__bridge id)kAXTrustedCheckOptionPrompt: @YES};
    if (AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)opts)) {
        // Already trusted (nothing to prompt) — reflect that immediately.
        [self refreshState];
        return;
    }
    // Keep the instructions readable while the user works in System Settings: tuck this window
    // against the left edge and float it there (instead of hiding it behind everything). Settings
    // opens centred with the Accessibility toggle on the RIGHT of its content, so the left edge
    // stays clear of it. refreshState restores the window to the centre once permission is granted.
    [self tuckAsideForSettings];
}

// Float the onboarding window against the left edge so its instructions stay visible as a how-to
// reference while the user is over in System Settings — without covering the Accessibility toggle.
- (void)tuckAsideForSettings {
    NSScreen *screen = self.window.screen ?: [NSScreen mainScreen];
    NSRect vf = screen.visibleFrame;
    NSRect wf = self.window.frame;
    // Tuck the welcome window against the LEFT edge at NORMAL level (NOT floating). System Settings
    // opens centred and sits ON TOP, fully usable — the welcome window stays visible behind it,
    // peeking out on the left. The user can click that peek to bring the instructions forward, read
    // them, then click back to Settings. (Floating it made it cover Settings and forced the user to
    // shuffle windows around — this is the fix for that.)
    CGFloat x = vf.origin.x + 24;
    CGFloat y = vf.origin.y + (vf.size.height - wf.size.height) / 2.0;
    self.window.hidesOnDeactivate = NO;        // stay visible (behind Settings) when it takes focus
    self.window.level = NSNormalWindowLevel;   // let Settings come over it, not the other way round
    [self.window setFrameOrigin:NSMakePoint(x, y)];
    [self.window orderFront:nil];
}

// Fallback for the rare case where the system prompt won't appear (previously dismissed, or the
// app is already listed): open the Accessibility pane directly.
- (void)openSettingsManually:(id)sender {
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"]];
    [self tuckAsideForSettings];
}

- (void)finishTapped:(id)sender {
    [self closeSystemSettings];
    [self.window close];
}

// System Settings (System Preferences on older macOS — same bundle id) is only opened to
// grant Accessibility. Close it once we're done so it isn't left sitting open behind Blinkered.
- (void)closeSystemSettings {
    for (NSRunningApplication *app in [NSRunningApplication
            runningApplicationsWithBundleIdentifier:@"com.apple.systempreferences"]) {
        [app terminate];
    }
}

- (void)windowWillClose:(NSNotification *)note {
    [self.pollTimer invalidate];
    self.pollTimer = nil;
    if (!self.finished) { self.finished = YES; if (self.onFinish) self.onFinish(); }
}

@end


#pragma mark - Auto-update setup card

// Is the root updater daemon already set up? Two install paths: the .pkg installer drops a plain
// LaunchDaemon at /Library/LaunchDaemons (one admin prompt at install, no card needed); the fallback
// (a DMG drag-install) uses the app-driven SMAppService card. Either means auto-updates are on — so the
// "Secure this device" card should NOT show. Checking the LaunchDaemon plist avoids the card redundantly
// registering a SECOND (SMAppService) daemon on top of the pkg's one.
static BOOL blinkeredUpdaterDaemonInstalled(void) {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/LaunchDaemons/app.blinkered.updater.plist"]) return YES;
    if (@available(macOS 13.0, *)) {
        return [SMAppService daemonServiceWithPlistName:@"app.blinkered.updater.plist"].status == SMAppServiceStatusEnabled;
    }
    return NO;
}

// A one-time, PARENT-facing card shown right after pairing on the kid's standard account (the parent is
// present and enters an admin password once). "Turn on" registers the root updater daemon via SMAppService
// so the app auto-updates on the kid's account forever. See docs/PARENT_SETUP_REGISTRATION.md. Modeled on
// BlinkeredOnboardingController; unlike Accessibility this step is OPTIONAL (has a "Not now"). Only shown
// when the daemon isn't already installed (e.g. a DMG drag-install); the .pkg installer sets it up, so the
// card is skipped there.
API_AVAILABLE(macos(13.0))
@interface BlinkeredAutoUpdateController : NSWindowController <NSWindowDelegate>
@property (nonatomic, strong) NSTimer *pollTimer;
@property (nonatomic, strong) NSTextField *statusPill;
@property (nonatomic, strong) NSTextField *liveStatus;
@property (nonatomic, strong) NSButton *turnOnButton;
@property (nonatomic, strong) NSButton *doneButton;
@property (nonatomic, copy) void (^onFinish)(void);
@property (nonatomic) BOOL finished;
@property (nonatomic) BOOL wasEnabled;
@end

@implementation BlinkeredAutoUpdateController

- (instancetype)init {
    NSWindow *win = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 560, 560)
        styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskFullSizeContentView)
        backing:NSBackingStoreBuffered defer:NO];
    win.titlebarAppearsTransparent = YES;
    win.titleVisibility = NSWindowTitleHidden;
    win.movableByWindowBackground = YES;
    win.level = NSNormalWindowLevel;
    self = [super initWithWindow:win];
    if (self) { win.delegate = self; [self buildUI]; }
    return self;
}

- (SMAppService *)service {
    return [SMAppService daemonServiceWithPlistName:@"app.blinkered.updater.plist"];
}

- (BOOL)isEnabled {
    return blinkeredUpdaterDaemonInstalled();   // pkg LaunchDaemon OR SMAppService
}

- (void)buildUI {
    NSView *c = self.window.contentView;
    c.wantsLayer = YES;
    CGFloat W = 560, H = 560;

    NSImageView *icon = [[NSImageView alloc] initWithFrame:NSMakeRect((W-80)/2, H-128, 80, 80)];
    icon.image = [NSApp applicationIconImage];
    icon.imageScaling = NSImageScaleProportionallyUpOrDown;
    [c addSubview:icon];

    [c addSubview:BlinkeredMakeLabel(@"Secure this device", 24, NSFontWeightBold, [NSColor labelColor], NSMakeRect(40, H-172, W-80, 32), NSTextAlignmentCenter)];
    [c addSubview:BlinkeredMakeLabel(@"One quick step keeps Blinkered up to date on your child's account.", 13, NSFontWeightRegular, [NSColor secondaryLabelColor], NSMakeRect(40, H-198, W-80, 20), NSTextAlignmentCenter)];

    NSView *card = [[NSView alloc] initWithFrame:NSMakeRect(40, 170, W-80, 190)];
    card.wantsLayer = YES;
    card.layer.backgroundColor = [NSColor colorWithCalibratedWhite:0.5 alpha:0.08].CGColor;
    card.layer.cornerRadius = 14;
    card.layer.borderWidth = 1;
    card.layer.borderColor = [[NSColor separatorColor] colorWithAlphaComponent:0.6].CGColor;
    [c addSubview:card];
    CGFloat CW = card.frame.size.width;

    [card addSubview:BlinkeredMakeLabel(@"Automatic updates", 16, NSFontWeightSemibold, [NSColor labelColor], NSMakeRect(22, 150, 260, 22), NSTextAlignmentLeft)];
    self.statusPill = BlinkeredMakeLabel(@"● Off", 12, NSFontWeightSemibold, [NSColor systemOrangeColor], NSMakeRect(CW-22-160, 151, 160, 20), NSTextAlignmentRight);
    [card addSubview:self.statusPill];

    [card addSubview:BlinkeredMakeLabel(
        @"Keeps Blinkered up to date on your child's account. You'll enter your Mac administrator password once. Your child never needs it.",
        12.5, NSFontWeightRegular, [NSColor secondaryLabelColor],
        NSMakeRect(22, 74, CW-44, 60), NSTextAlignmentLeft)];

    self.turnOnButton = [[NSButton alloc] initWithFrame:NSMakeRect(22, 22, CW-44, 38)];
    self.turnOnButton.title = @"Turn on…";
    self.turnOnButton.bezelStyle = NSBezelStyleRounded;
    self.turnOnButton.controlSize = NSControlSizeLarge;
    self.turnOnButton.keyEquivalent = @"\r";
    self.turnOnButton.font = [NSFont systemFontOfSize:14 weight:NSFontWeightSemibold];
    self.turnOnButton.target = self;
    self.turnOnButton.action = @selector(turnOnTapped:);
    [card addSubview:self.turnOnButton];

    self.liveStatus = BlinkeredMakeLabel(@"", 14, NSFontWeightSemibold, [NSColor secondaryLabelColor], NSMakeRect(40, 120, W-80, 26), NSTextAlignmentCenter);
    [c addSubview:self.liveStatus];

    self.doneButton = [[NSButton alloc] initWithFrame:NSMakeRect((W-220)/2, 58, 220, 38)];
    self.doneButton.title = @"Not now";
    self.doneButton.bezelStyle = NSBezelStyleRounded;
    self.doneButton.controlSize = NSControlSizeLarge;
    self.doneButton.target = self;
    self.doneButton.action = @selector(doneTapped:);
    [c addSubview:self.doneButton];

    [self refreshState];
}

- (void)showCard {
    // Popup level so the card is visible OVER the kiosk lock windows (NSMainMenuWindowLevel+2) when it's
    // re-invoked from the locked-session ⋯ menu. Harmless for the post-pairing (no-lock) case. The system
    // admin-auth dialog sits above this at its own level.
    self.window.level = NSPopUpMenuWindowLevel;
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [self.pollTimer invalidate];
    __weak typeof(self) ws = self;
    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t) { [ws refreshState]; }];
}

- (void)refreshState {
    if (self.isEnabled) {
        self.statusPill.stringValue = @"✓ On";
        self.statusPill.textColor = [NSColor systemGreenColor];
        self.liveStatus.stringValue = @"✓ Automatic updates are on.";
        self.liveStatus.font = [NSFont systemFontOfSize:18 weight:NSFontWeightBold];
        self.liveStatus.textColor = [NSColor systemGreenColor];
        self.turnOnButton.enabled = NO;
        self.doneButton.title = @"Done";
        self.doneButton.keyEquivalent = @"\r";
        if (!self.wasEnabled) {
            self.wasEnabled = YES;
            [self.window makeFirstResponder:self.doneButton];
        }
    } else {
        self.statusPill.stringValue = @"● Off";
        self.statusPill.textColor = [NSColor systemOrangeColor];
        self.turnOnButton.enabled = YES;
        self.doneButton.title = @"Not now";
        self.doneButton.keyEquivalent = @"";
    }
}

- (void)turnOnTapped:(id)sender {
    // F2 (P0): never register the SMAppService updater daemon when the .pkg has already installed the
    // /Library/LaunchDaemons job under the SAME Label (app.blinkered.updater) — two jobs under one Label is a
    // collision, and the pkg LaunchDaemon is the standardised (Enforced) mechanism. blinkeredShowAutoUpdate-
    // SetupThenQuit already skips showing this card when a daemon exists; this is a defensive backstop at the
    // registration point itself, so no entry path (dashboard re-invoke, race between show and tap) can
    // double-register. (Checks the pkg plist specifically: re-registering an already-Enabled SMAppService is
    // idempotent and fine.)
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/LaunchDaemons/app.blinkered.updater.plist"]) {
        DDLogInfo(@"Blinkered: pkg updater LaunchDaemon present — refusing to register the SMAppService variant (Label collision)");
        [self refreshState];
        return;
    }
    NSError *err = nil;
    BOOL ok = [self.service registerAndReturnError:&err];
    DDLogInfo(@"Blinkered: updater daemon register from card (ok=%d) status=%ld err=%@", ok, (long)self.service.status, err.localizedDescription);
    if (self.service.status == SMAppServiceStatusRequiresApproval) {
        self.liveStatus.stringValue = @"Approve “Blinkered” in System Settings ▸ Login Items…";
        self.liveStatus.font = [NSFont systemFontOfSize:13 weight:NSFontWeightRegular];
        self.liveStatus.textColor = [NSColor secondaryLabelColor];
        [SMAppService openSystemSettingsLoginItems];
    } else if (!ok && err) {
        self.liveStatus.stringValue = @"Couldn't turn on — an administrator password is required.";
        self.liveStatus.font = [NSFont systemFontOfSize:13 weight:NSFontWeightRegular];
        self.liveStatus.textColor = [NSColor systemRedColor];
    }
    [self refreshState];
}

- (void)doneTapped:(id)sender {
    [self.window close];
}

- (void)windowWillClose:(NSNotification *)note {
    [self.pollTimer invalidate];
    self.pollTimer = nil;
    if (!self.finished) { self.finished = YES; if (self.onFinish) self.onFinish(); }
}

@end


#pragma mark - Enforced setup (assisted-manual): Blinkered GUIDES and VERIFIES, never mutates

// Round-3 decision (DUAL_MODE_ONBOARDING_PHASE2_REVIEW.md): the automated account surgery was REJECTED.
// macOS's Users & Groups already performs create-admin + demote-child safely — it owns Secure-Token
// propagation (there is no public OpenDirectory API for that) and the last-admin guard. A hand-rolled root
// helper would reinvent both, and its failure mode is catastrophic (a parent admin who can't unlock
// FileVault = the family locked out of their Mac and data), versus manual's failure mode: a support ticket.
//
// So EVERYTHING below is read-only. No sysadminctl, no dseditgroup WRITE (-o edit), no OpenDirectory
// mutation, no token dance, no forced logout. We open the right pane, then observe. Setup stays PENDING
// until a demotion is actually observed — success is never claimed from a change this app didn't make.

// READ-ONLY membership check. 1 = admin, 0 = standard, -1 = unknown.
// `-o checkmember` is a pure query; the mutating verb would be `-o edit`, which we never use.
// Deliberately not scraping `id`/`groups` output — that varies by locale and breaks on names with spaces.
static int blinkeredRunningUserIsAdmin(void) {
    NSTask *t = [[NSTask alloc] init];
    t.executableURL = [NSURL fileURLWithPath:@"/usr/sbin/dseditgroup"];
    t.arguments = @[@"-o", @"checkmember", @"-m", NSUserName(), @"admin"];
    NSPipe *out = [NSPipe pipe];
    t.standardOutput = out;
    t.standardError = [NSPipe pipe];
    NSError *err = nil;
    if (![t launchAndReturnError:&err]) return -1;
    NSData *d = [out.fileHandleForReading readDataToEndOfFile];
    [t waitUntilExit];
    NSString *s = [[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] lowercaseString];
    if ([s hasPrefix:@"yes"]) return 1;
    if ([s hasPrefix:@"no"])  return 0;
    return -1;
}

// READ-ONLY ownership check: is our bundle root:wheel? That's the P1-3 boundary the .pkg establishes.
static BOOL blinkeredBundleIsRootOwned(void) {
    NSDictionary *a = [[NSFileManager defaultManager] attributesOfItemAtPath:[[NSBundle mainBundle] bundlePath]
                                                                       error:nil];
    if (!a) return NO;
    return [a[NSFileOwnerAccountID] intValue] == 0 && [a[NSFileGroupOwnerAccountID] intValue] == 0;
}

@interface BlinkeredEnforcedSetupController : NSWindowController <NSWindowDelegate>
@property (nonatomic, strong) NSTimer *pollTimer;
@property (nonatomic, strong) NSTextField *statusPill;
@property (nonatomic, strong) NSTextField *liveStatus;
@property (nonatomic, strong) NSButton *openSettingsButton;
@property (nonatomic, strong) NSButton *doneButton;
@property (nonatomic, copy) void (^onFinish)(void);
@property (nonatomic) BOOL finished;
@property (nonatomic) BOOL wasVerified;
@property (nonatomic) BOOL elevatedLevel;   // YES only over a kiosk lock (menu re-invoke); NO for setup
@end

@implementation BlinkeredEnforcedSetupController

- (instancetype)init {
    NSWindow *win = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 580, 700)
        styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskFullSizeContentView)
        backing:NSBackingStoreBuffered defer:NO];
    win.titlebarAppearsTransparent = YES;
    win.titleVisibility = NSWindowTitleHidden;
    win.movableByWindowBackground = YES;
    win.level = NSNormalWindowLevel;
    self = [super initWithWindow:win];
    if (self) { win.delegate = self; [self buildUI]; }
    return self;
}

// The single source of truth for "is Enforced actually set up?" — an OBSERVATION, not a stored flag.
- (BOOL)isVerified { return blinkeredRunningUserIsAdmin() == 0; }

- (void)buildUI {
    NSView *c = self.window.contentView;
    c.wantsLayer = YES;
    CGFloat W = 580, H = 700;

    NSImageView *icon = [[NSImageView alloc] initWithFrame:NSMakeRect((W-72)/2, H-100, 64, 64)];
    icon.image = [NSApp applicationIconImage];
    icon.imageScaling = NSImageScaleProportionallyUpOrDown;
    [c addSubview:icon];

    [c addSubview:BlinkeredMakeLabel(@"Finish protecting this Mac", 23, NSFontWeightBold, [NSColor labelColor],
                                     NSMakeRect(40, H-140, W-80, 30), NSTextAlignmentCenter)];
    [c addSubview:BlinkeredMakeLabel(@"Blinkered doesn't change your accounts — macOS does, so your files and passwords stay safe.",
                                     13, NSFontWeightRegular, [NSColor secondaryLabelColor],
                                     NSMakeRect(50, H-172, W-100, 30), NSTextAlignmentCenter)];

    NSView *card = [[NSView alloc] initWithFrame:NSMakeRect(40, 250, W-80, 270)];
    card.wantsLayer = YES;
    card.layer.backgroundColor = [NSColor colorWithCalibratedWhite:0.5 alpha:0.08].CGColor;
    card.layer.cornerRadius = 14;
    card.layer.borderWidth = 1;
    card.layer.borderColor = [[NSColor separatorColor] colorWithAlphaComponent:0.6].CGColor;
    [c addSubview:card];
    CGFloat CW = card.frame.size.width;

    [card addSubview:BlinkeredMakeLabel(@"In System Settings ▸ Users & Groups", 15, NSFontWeightSemibold,
                                        [NSColor labelColor], NSMakeRect(22, 238, 320, 22), NSTextAlignmentLeft)];
    self.statusPill = BlinkeredMakeLabel(@"● Not done yet", 12, NSFontWeightSemibold, [NSColor systemOrangeColor],
                                         NSMakeRect(CW-22-170, 239, 170, 20), NSTextAlignmentRight);
    [card addSubview:self.statusPill];

    // Five steps as ONE multi-line label so the layout survives copy tweaks. Step 2 (the account
    // switch) is mandatory, not optional: macOS greys out the "administrator" checkbox for the account
    // you're signed into, so a parent installing on the child's own account CANNOT demote it from
    // there — they must sign in as the parent account first. Found in the real-device demotion test.
    NSTextField *steps = BlinkeredMakeLabel(
        @"1.  If you don't already have your own Administrator account, add a new user and make it Administrator — that's your parent account.\n"
         "2.  Log out here and sign back in as your parent account (or switch users, if you've turned on Fast User Switching).\n"
         "3.  In Users & Groups, set your child's account to Standard.\n"
         "4.  Turn off the Guest user, and remove any account that isn't the parent or your child.\n"
         "5.  Restart the Mac, then have your child sign in to their Standard account.",
        12.5, NSFontWeightRegular, [NSColor labelColor], NSMakeRect(22, 80, CW-44, 150), NSTextAlignmentLeft);
    steps.cell.wraps = YES;
    [card addSubview:steps];
    [card addSubview:BlinkeredMakeLabel(@"macOS won't let you change the account you're signed into — that's why you sign in as the parent account first.",
                                        11, NSFontWeightRegular, [NSColor secondaryLabelColor],
                                        NSMakeRect(22, 54, CW-44, 24), NSTextAlignmentLeft)];

    self.openSettingsButton = [[NSButton alloc] initWithFrame:NSMakeRect(22, 12, CW-44, 38)];
    self.openSettingsButton.title = @"Open Users & Groups…";
    self.openSettingsButton.bezelStyle = NSBezelStyleRounded;
    self.openSettingsButton.controlSize = NSControlSizeLarge;
    self.openSettingsButton.keyEquivalent = @"\r";
    self.openSettingsButton.font = [NSFont systemFontOfSize:14 weight:NSFontWeightSemibold];
    self.openSettingsButton.target = self;
    self.openSettingsButton.action = @selector(openSettingsTapped:);
    [card addSubview:self.openSettingsButton];

    self.liveStatus = BlinkeredMakeLabel(@"", 14, NSFontWeightSemibold, [NSColor secondaryLabelColor],
                                         NSMakeRect(40, 182, W-80, 34), NSTextAlignmentCenter);
    [c addSubview:self.liveStatus];

    // The Recovery caveat (P0-4), stated HERE and not only on the website, because this card is where the
    // parent forms their expectation. Under-claim: never imply Enforced is absolute.
    [c addSubview:BlinkeredMakeLabel(@"Your child can still install apps, browse and game as normal — this only stops them removing Blinkered or making system-level changes on their everyday account. A tech-savvy child could still remove Blinkered using macOS Recovery; only a school-managed Mac can fully prevent that — so we'll also alert you if Blinkered is ever removed.",
                                     11.5, NSFontWeightRegular, [NSColor tertiaryLabelColor],
                                     NSMakeRect(50, 92, W-100, 84), NSTextAlignmentCenter)];

    self.doneButton = [[NSButton alloc] initWithFrame:NSMakeRect((W-220)/2, 44, 220, 36)];
    self.doneButton.title = @"Not now";
    self.doneButton.bezelStyle = NSBezelStyleRounded;
    self.doneButton.controlSize = NSControlSizeLarge;
    self.doneButton.target = self;
    self.doneButton.action = @selector(doneTapped:);
    [c addSubview:self.doneButton];

    [self refreshState];
}

- (void)showCard {
    // Normal level during setup (savepair path): the parent MUST switch accounts to finish, and a
    // pop-up-menu-level window floats OVER the macOS "Log Out" confirmation sheet and the Users &
    // Groups auth prompt — so an elevated card literally blocks the step it's asking for (a parent
    // reported "I couldn't log out because Blinkered was up"). Only elevate over an actual kiosk lock,
    // where the card is re-opened from the locked-session menu and must sit above the lock windows.
    self.window.level = self.elevatedLevel ? NSPopUpMenuWindowLevel : NSNormalWindowLevel;
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [self.pollTimer invalidate];
    __weak typeof(self) ws = self;
    // Poll the OBSERVATION, so the card self-completes the moment macOS reports the child is Standard.
    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *t) { [ws refreshState]; }];
}

- (void)refreshState {
    if (self.isVerified) {
        self.statusPill.stringValue = @"✓ Done";
        self.statusPill.textColor = [NSColor systemGreenColor];
        // Only claim "protected" when BOTH halves hold: the child is Standard AND the bundle is root-owned
        // (P1-3). A Standard child with an owner-writable bundle is NOT protected, and saying otherwise
        // would be the same over-claim this design exists to avoid.
        if (blinkeredBundleIsRootOwned()) {
            self.liveStatus.stringValue = @"✓ Your child is now a standard account — Blinkered is protected.";
            self.liveStatus.textColor = [NSColor systemGreenColor];
        } else {
            self.liveStatus.stringValue = @"✓ Your child is now a standard account. Reinstall from the parent installer to finish protecting Blinkered itself.";
            self.liveStatus.textColor = [NSColor systemOrangeColor];
        }
        self.liveStatus.font = [NSFont systemFontOfSize:13.5 weight:NSFontWeightBold];
        self.openSettingsButton.enabled = NO;
        self.doneButton.title = @"Done";
        self.doneButton.keyEquivalent = @"\r";
        if (!self.wasVerified) {
            self.wasVerified = YES;
            [self.window makeFirstResponder:self.doneButton];
            DDLogInfo(@"Blinkered: Enforced setup VERIFIED by observation — running user is now standard (rootOwned=%d)",
                      blinkeredBundleIsRootOwned());
        }
    } else {
        self.statusPill.stringValue = @"● Not done yet";
        self.statusPill.textColor = [NSColor systemOrangeColor];
        self.openSettingsButton.enabled = YES;
        self.doneButton.title = @"Not now";
        self.doneButton.keyEquivalent = @"";
    }
}

// Opening the pane is the ONLY action this card takes. macOS does the rest.
- (void)openSettingsTapped:(id)sender {
    NSURL *pane = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.Users-Groups-Settings.extension"];
    [[NSWorkspace sharedWorkspace] openURL:pane];
    self.liveStatus.stringValue = @"Waiting… this updates itself once your child is a standard account.";
    self.liveStatus.font = [NSFont systemFontOfSize:12.5 weight:NSFontWeightRegular];
    self.liveStatus.textColor = [NSColor secondaryLabelColor];
    DDLogInfo(@"Blinkered: Enforced setup — opened Users & Groups (guidance only; the app mutates nothing)");
}

- (void)doneTapped:(id)sender { [self.window close]; }

- (void)windowWillClose:(NSNotification *)note {
    [self.pollTimer invalidate];
    self.pollTimer = nil;
    if (!self.finished) { self.finished = YES; if (self.onFinish) self.onFinish(); }
}

@end


#pragma mark -

// Blinkered: content view of the menu-bar click shield — transparent per-screen strip windows
// that swallow clicks on the RIGHT HALF of the macOS menu bar while an elevated (locked) session
// shows it. The bar stays visible (clock, Wi-Fi, battery) but the status-item region is inert:
// third-party status items (clicking the Microsoft Defender shield wedged a locked MacBook,
// 11 Aug 2026), the Wi-Fi toggle (induced-offline attack — OFFLINE_UNLOCK review §B.5) and
// Control Center are all right-aligned and covered. The left half (Apple menu — already
// OS-disabled under a home lock — and the app menus) is intentionally left clickable. The
// mechanism is the one the exam covers already rely on (an elevated window over the strip
// receives the clicks instead of the status items); this is that cover, transparent and
// sized to the right half of the menu-bar strip.
@interface BlinkeredMenuBarShieldView : NSView
@end

@implementation BlinkeredMenuBarShieldView

// Consume the click even when another window is key, so the first click can't reach a status item.
- (BOOL)acceptsFirstMouse:(NSEvent *)event { return YES; }

// Terminate the responder chain for every mouse event class so nothing travels further.
- (void)mouseDown:(NSEvent *)event {}
- (void)mouseUp:(NSEvent *)event {}
- (void)rightMouseDown:(NSEvent *)event {}
- (void)rightMouseUp:(NSEvent *)event {}
- (void)otherMouseDown:(NSEvent *)event {}
- (void)otherMouseUp:(NSEvent *)event {}
- (void)scrollWheel:(NSEvent *)event {}

@end


#pragma mark - Blinkered atomic teardown (MAC_ATOMIC_TEARDOWN_PLAN.md)

// Set unconditionally at the top of exitSEB — a GATE only, never an early return there: the AAC
// double-entry (applicationShouldTerminate → terminateSEB → exitSEB) is designed behaviour and must
// keep working, and every exitSEB caller (page quit, /seb-quit, the offline master-code exit,
// requestedExit:) needs the disarm this flag guards. Process-wide static rather than an ivar because
// the bridge (SEBBrowserController, M1) reads it and SEBController is the app delegate singleton.
static BOOL _blinkeredTeardownStarted = NO;

// Read-only view of the teardown flag for code outside SEBController (declared in SEBController.h).
BOOL BlinkeredTeardownStarted(void) { return _blinkeredTeardownStarted; }

#pragma mark - Blinkered modal-safe main-thread wake-ups (OFFLINE_RETRY_DEAD_END_PLAN §4.2)

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// THE MEASUREMENT. Five ways to wake the main thread, all scheduled for t = 1.0 s, with an
// app-modal alert up from t = 0.1 s to t = 3.1 s and -runModal entered from inside a main-queue
// block — which is how -blinkeredHomeConnectivityFailed: raises the offline panel:
//
//     performSelector:…:inModes: + the modal modes   fired 1.00 s   ✓
//     dispatch_after on a PRIVATE serial queue       fired 1.04 s   ✓
//     performSelector:…:afterDelay: (default mode)   fired 3.11 s   ✗
//     dispatch_after on the MAIN queue               fired 3.11 s   ✗
//     NWPathMonitor pointed at the MAIN queue        fired 3.11 s   ✗
//
// In that probe "the modal's entire life" was 3 s because the probe ended it. On a stranded device
// nothing ends it: _blinkeredOfflinePanelShowing clears in exactly one place, the panel's own
// completion handler, which runs only when a human presses a button. So on the device the last
// three rows do not drift — THEY NEVER FIRE.
//
// THE TWO HALVES STARVE FOR DIFFERENT REASONS, and this is why one remedy is not enough:
//   • the perform starves on RUN-LOOP MODE — -runModal spins in NSModalPanelRunLoopMode and a
//     default-mode perform is not registered there. Naming the modes fixes it.
//   • the dispatches starve on SERIAL-QUEUE RE-ENTRANCY — the main queue is serial and -runModal is
//     running inside one of its blocks, so no later main-queue block can start until the panel
//     closes. Run-loop modes are irrelevant to it and `inModes:` cannot fix it.
// Writing the backoff as dispatch_after(main) is the more idiomatic choice and produces a bug that
// LOOKS IDENTICAL to the one §5 STAGE 3 fixed while being untouched by the same remedy. That is the
// single most likely way Fix 2 ships inert.
//
// So the retry path has exactly two main-thread wake-up primitives and they are both here, sliced
// and driven under a real modal session by run-home-retry-modal-safety-test.sh. NSRunLoopCommonModes
// is documented to include the other two in an AppKit app; both are named anyway, because assuming
// framework semantics is what produced every defect in this workstream. Naming a mode twice is
// harmless — the perform is one request and fires once.
// ═══════════════════════════════════════════════════════════════════════════════════════════════
// BEGIN blinkeredModalSafeWakeups
static NSArray *BlinkeredModalSafeRunLoopModes(void)
{
    return @[NSRunLoopCommonModes, NSModalPanelRunLoopMode, NSEventTrackingRunLoopMode];
}

// Delayed wake-up on the CURRENT thread's run loop (Fix 2 only ever calls this on the main thread).
// NOT dispatch_after: see the table above.
static void BlinkeredModalSafePerform(id target, SEL selector, NSTimeInterval delay)
{
    [target performSelector:selector withObject:nil afterDelay:delay inModes:BlinkeredModalSafeRunLoopModes()];
}

static void BlinkeredModalSafeCancelPerform(id target, SEL selector)
{
    [NSObject cancelPreviousPerformRequestsWithTarget:target selector:selector object:nil];
}

// Background → main hop. MANDATORY on this path: NWPathMonitor delivers on the queue it is handed
// (a private one, condition 9) and -loadRequest: must run on the main thread. NOT
// dispatch_async(main): that hop starved for the panel's whole life in the table above, which would
// mean Fix 2 fires only once the panel is gone — the inertness condition 4 exists to prevent,
// reintroduced where nobody would look for it.
static void BlinkeredModalSafeHopToMain(id target, SEL selector)
{
    [target performSelectorOnMainThread:selector withObject:nil waitUntilDone:NO
                                  modes:BlinkeredModalSafeRunLoopModes()];
}
// END blinkeredModalSafeWakeups

#pragma mark -

@interface SEBController ()
// Press-and-hold accent popover visibility in locked sessions (defined further below).
- (void) noteAccentPopoverActivity;
- (void) raiseAccentPopoverTick:(NSTimer *)timer;
- (void) raiseAccentPopoverPanels;
// P1 Bug-A paint recovery (see the module further below).
@property (nonatomic) BOOL blinkeredPaintArmed;
@property (nonatomic, strong) NSTimer *blinkeredPaintTimer;
@property (nonatomic, strong) dispatch_queue_t blinkeredPaintQueue;   // serial: paint capture runs OFF the main thread (a slow GPU capture must never stall the UI / starve WebKit's compositing)
@property (nonatomic) NSInteger blinkeredReloadCount;
@property (nonatomic) NSTimeInterval blinkeredLastPaintCheck;
@property (nonatomic) NSTimeInterval blinkeredLastWakeAt;
@property (nonatomic) BOOL blinkeredPaintGaveUp;   // unrecoverable this session — stop re-running the ladder
// Atomic teardown (M0): raw KVO removeObserver: throws on double-removal, and the teardown now removes
// the key-path observers before applicationWillTerminateProceed does. Sticky for the process — the
// observers are added once, in awakeFromNib, and never re-added.
@property (nonatomic) BOOL blinkeredKeyPathObserversRemoved;

// Foreign full-screen Space enforcement (#100). See the Space module further below.
@property (nonatomic) NSTimeInterval blinkeredLastSpaceRemedyAt;
@property (nonatomic) BOOL blinkeredInSpaceRemedy;              // -coverScreens <-> -blinkeredEnsureOrdinarySpace re-entrancy
@property (nonatomic, copy) NSString *blinkeredLastEnforcementKey;   // publish only on CHANGE
@property (nonatomic) NSInteger blinkeredEnforcementTickCounter;
@property (nonatomic) NSTimeInterval blinkeredLastAdjustScreenLockingAt;
@property (nonatomic) BOOL blinkeredAdjustScreenLockingTrailingScheduled;

// ── Fix 2: the home lock retries connectivity by itself (OFFLINE_RETRY_DEAD_END_PLAN §4) ────────
// Declared here, defined in the module beside the offline panel further below. -blinkeredPaintLockActive
// and -blinkeredArmPaintRecovery sit thousands of lines above that module and must reach it:
// condition 5 requires Fix 2's budgets to reset in the SAME place as the wake edge's, not in a
// separate one that a later session can forget to keep in step.
- (void)blinkeredHomeRetryResetForSession;
- (void)blinkeredHomeRetryArm;
- (void)blinkeredHomeRetryFire;
- (void)blinkeredHomeRetryPathBecameSatisfied;
- (void)blinkeredContentCommitted:(NSNotification *)n;
- (void)blinkeredHomeRetryCancelForTeardown;
- (void)blinkeredHomeRetryScheduleAfterSkip;
- (void)blinkeredResetOfflinePanelOutageLatch;
/// Shared by BOTH recovery navigators (condition 5 / review F11 scenario A): the wake-edge wedge
/// reload and Fix 2's retry must not issue a loadRequest: on top of each other's in-flight one.
- (BOOL)blinkeredNavigationInFlight;
/// Marked at the ONE shared navigation seam, -blinkeredIssueRecoveryNavigation:webView:, so every
/// recovery caller (panel Retry, wake-edge wedge reload, Fix 2) marks it without knowing it exists.
- (void)blinkeredNoteRecoveryNavigationIssued;
- (BOOL)blinkeredIssueRecoveryNavigation:(NSURL *)target webView:(WKWebView *)wk;
@end

@implementation SEBController


#pragma mark - Properties and Accessors

@synthesize f3Pressed;	//create getter and setter for F3 key pressed flag
@synthesize quittingMyself;	//create getter and setter for flag that SEB is quitting itself
@synthesize quittingSession;
@synthesize capWindows;
@synthesize lockdownWindows;

- (NSString *)accessibilityMessageString {
    return [NSString stringWithFormat:NSLocalizedString(@"%@ needs Accessibility permissions to read the title of the active (frontmost) window of any app for screen proctoring. %@ is using these Accessiblilty permissions ONLY during screen proctoring sessions. Grant access to %@ in System Settings / Security & Privacy / Accessibility.", @""), SEBShortAppName, SEBShortAppName, SEBFullAppNameClassic];
}

- (NSString *)privacyFilesFoldersMessageString {
    return [NSString stringWithFormat:NSLocalizedString(@"Grant access in System Settings / Privacy & Security / Files & Folders / %@.", @""), SEBFullAppNameClassic];
}

- (SEBOSXSessionState *) sessionState
{
    if (!_sessionState) {
        _sessionState = [[SEBOSXSessionState alloc] init];
    }
    return _sessionState;
}


- (AssessmentConfigurationManager *) assessmentConfigurationManager
{
    if (!_assessmentConfigurationManager) {
        _assessmentConfigurationManager = [AssessmentConfigurationManager new];
    }
    return _assessmentConfigurationManager;
}


- (SEBFileManager *) sebFileManager
{
    if (!_sebFileManager) {
        _sebFileManager = [[SEBFileManager alloc] init];
    }
    return _sebFileManager;
}


- (SEBOSXConfigFileController *) configFileController
{
    if (!_configFileController) {
        _configFileController = [[SEBOSXConfigFileController alloc] init];
        _configFileController.sebController = self;
    }
    return _configFileController;
}


- (SEBOSXBrowserController *) browserController
{
    if (!_browserController) {
        _browserController = [[SEBOSXBrowserController alloc] init];
        _browserController.sebController = self;
    }
    return _browserController;
}


- (ProcessListViewController *) processListViewController
{
    if (!_processListViewController) {
        _processListViewController = [[ProcessListViewController alloc] initWithNibName:@"ProcessListView" bundle:nil];
        _processListViewController.delegate = self;
    }
    return _processListViewController;
}


- (SEBBatteryController *) batteryController
{
    if (!_batteryController) {
        _batteryController = [[SEBBatteryController alloc] init];
    }
    return _batteryController;
}


- (AboutWindowController *) aboutWindowController
{
    if (!_aboutWindowController) {
        _aboutWindowController = [[AboutWindowController alloc] initWithWindow:_aboutWindow];
    }
    return _aboutWindowController;
}


- (HUDController *) hudController
{
    if (!_hudController) {
        _hudController = [[HUDController alloc] init];
    }
    return _hudController;
}


- (SEBOSXLockedViewController*)sebLockedViewController
{
    _sebLockedViewController.sebController = self;
    return _sebLockedViewController;
}


- (ServerController *)serverController
{
    if (!_serverController) {
        _serverController = [[ServerController alloc] init];
        _serverController.delegate = self;
    }
    return _serverController;
}


- (SEBScreenProctoringController *)screenProctoringController
{
    if (!_screenProctoringController) {
        _screenProctoringController = [[SEBScreenProctoringController alloc] init];
        _screenProctoringController.delegate = self;
        _screenProctoringController.spsControllerUIDelegate = self;
    }
    return _screenProctoringController;
}


- (TransmittingCachedScreenShotsViewController *) transmittingCachedScreenShotsViewController
{
    if (!_transmittingCachedScreenShotsViewController) {
        _transmittingCachedScreenShotsViewController = [[TransmittingCachedScreenShotsViewController alloc] initWithNibName:@"TransmittingCachedScreenShotsView" bundle:nil];
        _transmittingCachedScreenShotsViewController.uiDelegate = self;
    }
    return _transmittingCachedScreenShotsViewController;
}


- (SEBZoomController *)zoomController
{
    if (!_zoomController) {
        _zoomController = [[SEBZoomController alloc] init];
//        _zoomController.proctoringUIDelegate = self;
    }
    return _zoomController;
}


#pragma mark - Class and Instance Initialization

+ (void) initialize
{
    [[MyGlobals sharedMyGlobals] setFinishedInitializing:NO];
    [[MyGlobals sharedMyGlobals] setStartKioskChangedPresentationOptions:NO];
    [[MyGlobals sharedMyGlobals] setLogLevel:DDLogLevelDebug];
    
    SEBWindowSizeValueTransformer *windowSizeTransformer = [[SEBWindowSizeValueTransformer alloc] init];
    [NSValueTransformer setValueTransformer:windowSizeTransformer
                                    forName:@"SEBWindowSizeTransformer"];
    
    BoolValueTransformer *boolValueTransformer = [[BoolValueTransformer alloc] init];
    [NSValueTransformer setValueTransformer:boolValueTransformer
                                    forName:@"BoolValueTransformer"];
    
    IsEmptyCollectionValueTransformer *isEmptyCollectionValueTransformer = [[IsEmptyCollectionValueTransformer alloc] init];
    [NSValueTransformer setValueTransformer:isEmptyCollectionValueTransformer
                                    forName:@"isEmptyCollectionValueTransformer"];
    
    NSTextFieldNilToEmptyStringTransformer *textFieldNilToEmptyStringTransformer = [[NSTextFieldNilToEmptyStringTransformer alloc] init];
    [NSValueTransformer setValueTransformer:textFieldNilToEmptyStringTransformer
                                    forName:@"NSTextFieldNilToEmptyStringTransformer"];
}


- (id)init {
    self = [super init];
    if (self) {
        // Get SEB's PID
        NSRunningApplication *sebRunningApp = [NSRunningApplication currentApplication];
        sebPID = [sebRunningApp processIdentifier];

        _modalAlertWindows = [NSMutableArray new];
        _startingUp = true;
        self.systemManager = [[SEBSystemManager alloc] init];
        
        // Initialize console loggers
#ifdef DEBUG
        // We show log messages only in Console.app and the Xcode console in debug mode
        [DDLog addLogger:[DDOSLogger sharedInstance]];
#endif
        
        // Initialize a temporary logger unconditionally with the Debug log level
        // and the standard log file path, so SEB can log startup events before
        // settings are initialized
        [self initializeTemporaryLogger];
        
        [[MyGlobals sharedMyGlobals] setPreferencesReset:NO];
        [[MyGlobals sharedMyGlobals] setCurrentConfigURL:nil];
        [MyGlobals sharedMyGlobals].reconfiguredWhileStarting = NO;
        
        if (!_inactiveScreenWindows) {
            _inactiveScreenWindows = [NSMutableArray new];
        }
        
        // Add an observer for the request to unconditionally exit SEB
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(requestedExit:)
                                                     name:@"requestExitNotification" object:nil];
        
        
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        
        // Set default preferences for the case there are no user prefs yet
        // and set flag for displaying alert to new users
        firstStart = [preferences setSEBDefaults];
        // If reverting local client settings to default, allow to open Settings
        [[NSUserDefaults standardUserDefaults] setSecureBool:YES forKey:@"org_safeexambrowser_SEB_allowPreferencesWindow"];

        // Check if there is a SebClientSettings.seb file saved in the preferences directory
        [self.configFileController reconfigureClientWithSebClientSettings];
        
        // Initialize file logger if it's enabled in client (!) settings,
        // from this point on settings for log level and directory are considered
        [self initializeLogger];
        
        // Get default WebKit browser User Agent and create
        // default SEB User Agent
        _temporaryWebView = [WKWebView new];
        [_temporaryWebView evaluateJavaScript:@"navigator.userAgent" completionHandler:^(NSString *defaultUserAgent, NSError * _Nullable error) {
            [SEBBrowserController createSEBUserAgentFromDefaultAgent:defaultUserAgent];
            self.temporaryWebView = nil;
            DDLogInfo(@"Default browser user agent string: %@", [[MyGlobals sharedMyGlobals] valueForKey:@"defaultUserAgent"]);
        }];

        // Cache current settings for Siri and dictation
        [_systemManager cacheCurrentSystemSettings];

        // Regardless if switching to third party applications is allowed in current settings,
        // we need to first open the background cover windows with standard window levels
        [preferences setSecureBool:NO forKey:@"org_safeexambrowser_elevateWindowLevels"];

        _reloadPageUIElement = [ReloadPageUIElement new];
    }
    return self;
}


#pragma mark - Initialization When UI Is Available

- (void)awakeFromNib
{
    DDLogDebug(@"%s", __FUNCTION__);
    
//    NSApplicationPresentationOptions presentationOptions = (NSApplicationPresentationDisableForceQuit + NSApplicationPresentationHideDock);
//    DDLogDebug(@"NSApp setPresentationOptions: %lo", presentationOptions);
//    [NSApp setPresentationOptions:presentationOptions];

    // Flag initializing
    quittingMyself = false; //flag to know if quit application was called externally
    
    // Terminate invisibly running applications
    if ([NSRunningApplication respondsToSelector:@selector(terminateAutomaticallyTerminableApplications)]) {
        [NSRunningApplication terminateAutomaticallyTerminableApplications];
    }
    
    // Save the bundle ID of all currently running apps which are visible in a array
    NSArray *runningApps = [[NSWorkspace sharedWorkspace] runningApplications];
    NSRunningApplication *iterApp;
    visibleApps = [NSMutableArray array]; //array for storing bundleIDs of visible apps
    
    for (iterApp in runningApps) {
        BOOL isHidden = [iterApp isHidden];
        NSString *appBundleID = [iterApp valueForKey:@"bundleIdentifier"];
        DDLogInfo(@"Running app: %@, bundle ID: %@", iterApp.localizedName, appBundleID);
        if ((appBundleID != nil) & !isHidden) {
            [visibleApps addObject:appBundleID]; //add ID of the visible app
        }
        if ([iterApp ownsMenuBar]) {
            DDLogDebug(@"App %@ owns menu bar", iterApp);
        }
    }
    
    [[ProcessManager sharedProcessManager] updateMonitoredProcesses];
    
    /// Setup Notifications
    
    // Add an observer for the notification that another application became active (SEB got inactive)
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(regainActiveStatus:)
                                                 name:NSApplicationDidResignActiveNotification
                                               object:NSApp];
    
    //#ifndef DEBUG
    // Add an observer for the notification that another application was unhidden by the finder
    NSWorkspace *workspace = [NSWorkspace sharedWorkspace];
    [[workspace notificationCenter] addObserver:self
                                       selector:@selector(regainActiveStatus:)
                                           name:NSWorkspaceDidActivateApplicationNotification
                                         object:nil];
    
    // Add an observer for the notification that another application was unhidden by the finder
    [[workspace notificationCenter] addObserver:self
                                       selector:@selector(regainActiveStatus:)
                                           name:NSWorkspaceDidUnhideApplicationNotification
                                         object:nil];
    
    // Add an observer for the notification that another application was unhidden by the finder
    //    [[workspace notificationCenter] addObserver:self
    //                                       selector:@selector(regainActiveStatus:)
    //                                           name:NSWorkspaceWillLaunchApplicationNotification
    //                                         object:nil];
    //
    // Add an observer for the notification that another application was launched
    [[workspace notificationCenter] addObserver:self
                                       selector:@selector(appLaunch:)
                                           name:NSWorkspaceDidLaunchApplicationNotification
                                         object:nil];
    
    // Add key/value observing for any new application/process being run
    // also background apps or for apps that have the LSUIElement key in their Info.plist file
    static const void *kMyKVOContext = (void*)&kMyKVOContext;

    [[NSWorkspace sharedWorkspace] addObserver:self
                                    forKeyPath:@"runningApplications"
                                       options:NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld
                                       context:NULL];
    
    [[NSWorkspace sharedWorkspace] addObserver:self
                                    forKeyPath:@"isTerminated"
                                       options:NSKeyValueObservingOptionNew // maybe | NSKeyValueObservingOptionInitial
                                       context:NULL];
    
    // Add an observer for the notification that another application was unhidden by the finder
    [[workspace notificationCenter] addObserver:self
                                       selector:@selector(spaceSwitch:)
                                           name:NSWorkspaceActiveSpaceDidChangeNotification
                                         object:nil];
    
    //#endif
    // Add an observer for the notification that SEB became active
    // With third party apps and Flash fullscreen it can happen that SEB looses its
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(SEBgotActive:)
                                                 name:NSApplicationDidBecomeActiveNotification
                                               object:NSApp];
    
    // Add an observer for changes of the Presentation Options
    [NSApp addObserver:self
            forKeyPath:@"currentSystemPresentationOptions"
               options:NSKeyValueObservingOptionNew
               context:NULL];
    
    sebInstance = [NSRunningApplication currentApplication];
    
    [sebInstance addObserver:self
                  forKeyPath:@"isActive"
                     options:NSKeyValueObservingOptionNew
                     context:NULL];
    
    // Add a observer for changes of the screen configuration
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(adjustScreenLocking:)
                                                 name:NSApplicationDidChangeScreenParametersNotification
                                               object:NSApp];
    
    // Add a observer for notification that the main browser window changed screen
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(changeMainScreen:)
                                                 name:@"mainScreenChanged" object:nil];
    
    // Add an observer for the request to conditionally exit SEB
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(requestedQuit:)
                                                 name:@"requestQuitNotification" object:nil];
    
    // Add an observer for the request to conditionally quit SEB with asking quit password
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(quitLinkDetected:)
                                                 name:@"quitLinkDetected" object:nil];

    // [R1-5] Blinkered: a home-session load of our own content failed with a connectivity-class
    // error (offline / DNS / timeout / TLS-trust — posted by SEBAbstractWebView), or our cert
    // trust evaluation rejected a forged blinkered.com.au certificate (posted by
    // SEBBrowserController — that failure often surfaces as a swallowed −999, so it can't be
    // caught at the load-failure method). Show the native offline panel that names the way out.
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(blinkeredHomeConnectivityFailed:)
                                                 name:@"blinkeredHomeConnectivityFailed" object:nil];
    
    // Add an observer for the request to quit SEB or session unconditionally
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(quitSEBOrSession)
                                                 name:@"requestQuitSEBOrSession" object:nil];
    
    // Add an observer for the request to start the kiosk mode
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(startKioskMode)
                                                 name:@"requestStartKioskMode" object:nil];
    
    // Add an observer for the request to reinforce the kiosk mode
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(requestedReinforceKioskMode:)
                                                 name:@"requestReinforceKioskMode" object:nil];
    
    // Add an observer for the request to show about panel
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(requestedShowAbout:)
                                                 name:@"requestShowAboutNotification" object:nil];
    
    // Add an observer for the request to close about panel
    [[NSNotificationCenter defaultCenter] addObserver:self.aboutWindowController
                                             selector:@selector(closeAboutWindow:)
                                                 name:@"requestCloseAboutWindowNotification" object:nil];
    
    // Add an observer for the request to show help
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(requestedShowHelp:)
                                                 name:@"requestShowHelpNotification" object:nil];
    
    // Add an observer for the notification that preferences were closed
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(preferencesClosed:)
                                                 name:@"preferencesClosed" object:nil];
    
    // Add an observer for the notification that preferences were closed and SEB should be restarted
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(preferencesClosedRestartSEB:)
                                                 name:@"preferencesClosedRestartSEB" object:nil];
    // Add an observer for the notification that a previously interrupted exam was re-opened
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(lockSEB:)
                                                 name:@"detectedReOpeningExam" object:nil];
    // Add an observer for the notification that a screen sharing session become active
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(lockSEB:)
                                                 name:@"detectedScreenSharing" object:nil];
    // Add an observer for the notification that Siri was invoked
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(lockSEB:)
                                                 name:@"detectedSiri" object:nil];
    // Add an observer for the notification that dictation was invoked
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(lockSEB:)
                                                 name:@"detectedDictation" object:nil];
    // Add an observer for the notification that a prohibited process was started
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(lockSEB:)
                                                 name:@"detectedProhibitedProcess" object:nil];
    // Add an observer for the notification that a previously interrupted exam was re-opened
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(lockSEB:)
                                                 name:@"detectedSIGSTOP" object:nil];
    // Add an observer for the notification that a there is no required built-in display available
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(lockSEB:)
                                                 name:@"detectedRequiredBuiltinDisplayMissing" object:nil];
    // Add an observer for the notification that proctoring failed
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(lockSEB:)
                                                 name:@"proctoringFailed" object:nil];
    // Add an observer for the notification when SEB is locked by SEB Server
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(lockSEB:)
                                                 name:@"lockSEB" object:nil];
    // Add an observer for the notification necessary for the correct key view loop
    // for tabbing/VoiceOver through the browser window (toolbar) and Dock
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(goToDockButtonBecameFirstResponder)
                                                 name:@"goToDockButtonBecameFirstResponder" object:nil];

    
    [NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskKeyDown handler:^NSEvent *(NSEvent *event)
     {
        BOOL isLeftOption = (event.modifierFlags & NX_DEVICELALTKEYMASK) != 0;
        BOOL isLeftShift = (event.modifierFlags & NX_DEVICELSHIFTKEYMASK) != 0;
        BOOL isShift = (event.modifierFlags & NX_SHIFTMASK) != 0;
        BOOL isControl = (event.modifierFlags & NX_CONTROLMASK) != 0;
        // Blinkered: keep the macOS press-and-hold accent popover (à á â …) visible in locked
        // sessions. The popover is an NSPanel at NSDockWindowLevel (20); our elevated browser
        // windows sit above it (NSMainMenuWindowLevel+3), so it's created hidden behind them.
        // On a plain character key (no shortcut modifiers) we briefly watch for that panel and
        // raise it above the browser window — see -noteAccentPopoverActivity. No-op when window
        // levels aren't elevated (normal windows show the popover natively).
        if (!(event.modifierFlags & (NSEventModifierFlagCommand | NSEventModifierFlagControl | NSEventModifierFlagOption))) {
            [self noteAccentPopoverActivity];
        }
        self.tabPressedWhileDockIsKeyWindow = NO;
        self.tabPressedWhileWebViewIsFirstResponder = NO;
        self.shiftTabPressedWhileDockIsKeyWindow = NO;
        self.shiftTabPressedWhileWebViewIsFirstResponder = NO;
        if (isShift && event.keyCode == 48) { //Shift + Tab
            NSResponder *firstResponder = NSApp.keyWindow.firstResponder;
            if (NSApp.keyWindow == self.dockController.window) {
                self.shiftTabPressedWhileDockIsKeyWindow = YES;
            } else if (firstResponder.class == SEBOSXWKWebView.class || [firstResponder.className isEqualToString:@"WebHTMLView"]) {
                self.shiftTabPressedWhileWebViewIsFirstResponder = YES;
            } else if (firstResponder.class == SEBGoToDockButton.class && ([((NSButton *)firstResponder).identifier isEqualToString:@"toolbarGoToDockButton"] ||
                                                                           [((NSButton *)firstResponder).identifier isEqualToString:@"accessoryViewGoToDockButton"])) {
                [self.dockController activateDockFirstControl:NO];
                return nil;
            }
        } else if (event.keyCode == 48) { //Tab
            NSResponder *firstResponder = NSApp.keyWindow.firstResponder;
            id focusedUIElement = firstResponder.accessibilityFocusedUIElement;
            DDLogDebug(@"Tab key pressed, current key window: %@, current first responder: %@, current accessibilityFocusedUIElement: %@", NSApp.keyWindow, firstResponder, focusedUIElement);
            if (firstResponder.class == SEBBrowserWindow.class) {
                // This selects the first element on a web page directly after opening a new window
                // and pressing tab (without having to click the browser window first)
                [(SEBBrowserWindow *)firstResponder makeFirstResponder:[(SEBBrowserWindow *)firstResponder nativeWebView]];
            } else if (firstResponder.class == SEBOSXWKWebView.class || [firstResponder.className isEqualToString:@"WebHTMLView"]) {
                self.tabPressedWhileWebViewIsFirstResponder = YES;
            } else if (NSApp.keyWindow == self.dockController.window) {
                self.tabPressedWhileDockIsKeyWindow = YES;
            } else if (firstResponder.class == SEBGoToDockButton.class && [((NSButton *)firstResponder).identifier isEqualToString:@"accessoryViewGoToDockButton"]) {
                [self.browserController focusFirstElementInCurrentWindow];
                return nil;
            }
            
        }
        if (isLeftOption && !isLeftShift && event.keyCode == 48) {
            DDLogDebug(@"Left Option + Tab Key pressed!");
            [self.browserController activateNextOpenWindow];
            return nil;
        } else if (isLeftOption && isLeftShift && event.keyCode == 48) {
            DDLogDebug(@"Left Option + Left Shift + Tab Key pressed!");
            [self.browserController activatePreviousOpenWindow];
            return nil;
        } else if ((isControl || isShift) && event.keyCode == 0x63 ) {  //Ctrl/Shift + F3
            if (NSApp.keyWindow == self.dockController.window) {
                [self.browserController activateCurrentWindow];
            } else {
                [self.dockController activateDockFirstControl:YES];
            }
            return nil;
        } else if (event.keyCode == 0x63 ) {  //F3
            self->f3Pressed = YES;
            return nil;
        } else if (event.keyCode == 0x61 ) {  //F6
            if (self->f3Pressed) {    //if F3 got pressed before
                self->f3Pressed = NO;
                [self openPreferences:self]; //show preferences window
            }
            return nil;
        } else if (NSApp.keyWindow == self.dockController.window) {
            if (event.keyCode == kVK_UpArrow) {   //Cursor Up
                DDLogDebug(@"Cursor Up Key inside Dock pressed!");
                [self.dockController.window.firstResponder rightMouseDown:[NSEvent new]];
                return event;
            } else {
                return event;
            }
        }
        return event;
    }];
    
    
    // Blinkered: allow display sleep during a lock — do NOT hold the NoDisplaySleep assertion. SEB keeps
    // the display awake so an exam stays visible to a proctor, but that also keeps the WHOLE system awake
    // (macOS won't idle-sleep while the display is forced on, like `caffeinate -d`) — which cancels out the
    // idle-sleep allowance in MySleepCallBack, so a home-locked Mac never actually sleeps. Letting the
    // display sleep lets the system then idle-sleep → the agent's sleep beacon surfaces "Sleeping", and it
    // re-locks on wake. assertionID1 stays 0 so the IOPMAssertionRelease at kiosk-end is a harmless no-op.
    assertionID1 = 0;
    
    /*    // Prevent idle sleep
     success = IOPMAssertionCreateWithName(
     kIOPMAssertionTypeNoIdleSleep,
     kIOPMAssertionLevelOn,
     CFSTR("Safe Exam Browser Kiosk Mode"),
     &assertionID2);
     #ifdef DEBUG
     if (success == kIOReturnSuccess) {
     DDLogDebug(@"Idle sleep is switched off now.");
     }
     #endif
     */
    // Installing I/O Kit sleep/wake notification to cancel sleep
    
    IONotificationPortRef notifyPortRef; // notification port allocated by IORegisterForSystemPower
    io_object_t notifierObject; // notifier object, used to deregister later
    void* refCon = NULL; // this parameter is passed to the callback
    
    // register to receive system sleep notifications
    
    root_port = IORegisterForSystemPower( refCon, &notifyPortRef, MySleepCallBack, &notifierObject );
    if ( root_port == 0 )
    {
        DDLogError(@"IORegisterForSystemPower failed");
    } else {
        // add the notification port to the application runloop
        CFRunLoopAddSource( CFRunLoopGetCurrent(),
                           IONotificationPortGetRunLoopSource(notifyPortRef), kCFRunLoopCommonModes );
    }
    
    // Handling of Hotkeys for Preferences-Window
    f3Pressed = FALSE; //Initialize flag for first hotkey
}


- (void)removeKeyPathObservers
{
    if (_blinkeredKeyPathObserversRemoved) return;
    _blinkeredKeyPathObserversRemoved = YES;
    [NSApp removeObserver:self
            forKeyPath:@"currentSystemPresentationOptions"];
    [[NSWorkspace sharedWorkspace] removeObserver:self
            forKeyPath:@"runningApplications"];
    [[NSWorkspace sharedWorkspace] removeObserver:self
            forKeyPath:@"isTerminated"];
//    [NSApp removeObserver:self
//            forKeyPath:@"isActive"];
    [self blinkeredDisarmPaintRecovery];   // P1 Bug-A: tear down the paint-recovery observers + timer
}


- (void) firstDOMElementDeselected
{
    if (self.shiftTabPressedWhileWebViewIsFirstResponder) {
        [self.dockController activateDockFirstControl:NO];
    }
}

- (void) lastDOMElementDeselected
{
    if (self.tabPressedWhileWebViewIsFirstResponder) {
        [self.dockController activateDockFirstControl:YES];
    }
}

- (void) lastDockItemResignedFirstResponder
{
    if (self.tabPressedWhileDockIsKeyWindow) {
        [self.browserController activateInitialFirstResponderInCurrentWindow];
    }
}

- (void) firstDockItemResignedFirstResponder
{
    if (self.shiftTabPressedWhileDockIsKeyWindow) {
        [self.browserController focusLastElementInCurrentWindow];
    }
}

- (void) goToDockButtonBecameFirstResponder
{
    if (self.tabPressedWhileWebViewIsFirstResponder) {
        [self.dockController activateDockFirstControl:YES];
    }
}


- (id) currentDockAccessibilityParent
{
    return self.browserController.activeBrowserWindow.contentView;
}


#pragma mark - Application Delegate Methods
// (in order they are called)

// Blinkered: tracks whether we've released the locked web content's audio because the device is idle.
static BOOL blinkeredAudioSuspended = NO;

- (void)applicationWillFinishLaunching:(NSNotification *)notification
{
    DDLogDebug(@"%s", __FUNCTION__);

    // Create keyboard CGEvent for Return Key which is needed to close
    // a font download dialog which might be opened on some webpages
    keyboardEventReturnKey = CGEventCreateKeyboardEvent (NULL, (CGKeyCode)36, true);
    
    [[[NSWorkspace sharedWorkspace] notificationCenter]
     addObserver:self
     selector:@selector(lockSEB:)
     name:NSWorkspaceSessionDidBecomeActiveNotification
     object:nil];
    
    [[[NSWorkspace sharedWorkspace] notificationCenter]
     addObserver:self
     selector:@selector(lockSEB:)
     name:NSWorkspaceSessionDidResignActiveNotification
     object:nil];

    // Blinkered: idle-audio watchdog (battery). A locked media site (ABC/BBC/Khan…) holds an audio
    // channel open, so macOS refuses to idle-sleep — a locked Mac then never sleeps and drains the
    // battery. While the device sits idle (no keyboard/trackpad input) we release that audio so
    // coreaudiod lets go and the Mac can idle-sleep; the moment the child touches it, we restore it.
    // Only SILENT audio is ever touched (see the script in SEBAbstractModernWebView), so audible
    // playback the child is watching is never interrupted. Blinkered.app only runs while locked, so
    // this is effectively scoped to a lockdown session.
    __weak typeof(self) weakSelf = self;
    [NSTimer scheduledTimerWithTimeInterval:5.0 repeats:YES block:^(NSTimer * _Nonnull timer) {
        CFTimeInterval idle = CGEventSourceSecondsSinceLastEventType(kCGEventSourceStateHIDSystemState, kCGAnyInputEventType);
        if (idle > 90.0 && !blinkeredAudioSuspended) {
            blinkeredAudioSuspended = YES;
            [weakSelf.browserController blinkeredSetWebViewAudioSuspended:YES];
        } else if (idle < 5.0 && blinkeredAudioSuspended) {
            blinkeredAudioSuspended = NO;
            [weakSelf.browserController blinkeredSetWebViewAudioSuspended:NO];
        }
    }];
}


// Prevent an untitled document to be opened at application launch
- (BOOL) applicationShouldOpenUntitledFile:(NSApplication *)sender {
    DDLogDebug(@"Invoked applicationShouldOpenUntitledFile with answer NO!");
    return NO;
}


// Tells the application delegate to open a single file.
// Returning YES if the file is successfully opened, and NO otherwise.
//
- (BOOL)application:(NSApplication *)theApplication openFile:(NSString *)filename
{
    if (filename) {
        NSURL *fileURL = [NSURL fileURLWithPathString:filename];
        DDLogDebug(@"%s file URL: %@", __FUNCTION__, fileURL);

        if (!_openingSettings) {
            _openingSettings = YES;
            if (_startingUp && !_alternateKeyPressed && !self.settingsOpen) {
                _openedURL = YES;
                DDLogDebug(@"%s Delay opening file %@ while starting up.", __FUNCTION__, filename);
                _openingSettingsFileURL = fileURL;
            } else {
                // Opening a session config: cover the desktop right away (launch cleanup #2).
                [self blinkeredEarlyCoverScreens];
                [self openFile:fileURL];
            }
        }
        return YES;
    } else {
        return NO;
    }
}


- (void)application:(NSApplication *)sender openURLs:(nonnull NSArray<NSURL *> *)urls
{
    DDLogDebug(@"%s", __FUNCTION__);

    // Check if any alerts are open in SEB, abort opening if yes
    if (_modalAlertWindows.count) {
        DDLogError(@"%lu Modal window(s) displayed, aborting before opening new settings.", (unsigned long)_modalAlertWindows.count);
        return;
    }
    
    NSURL *url = urls.firstObject;
    if (url.isFileURL) {
        [self application:sender openFile:url.absoluteString];
    } else if ([url.scheme isEqualToString:@"blinkered"]) {
        if ([url.host isEqualToString:@"join"] && !_openingSettings) {
            NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            NSString *code = nil;
            NSString *studentName = nil;
            NSString *childId = nil;
            NSString *deviceId = nil;
            for (NSURLQueryItem *item in components.queryItems) {
                if ([item.name isEqualToString:@"code"]) code = item.value;
                if ([item.name isEqualToString:@"name"]) studentName = item.value;
                if ([item.name isEqualToString:@"childId"]) childId = item.value;
                if ([item.name isEqualToString:@"deviceId"]) deviceId = item.value;
            }
            if (code.length > 0) {
                // Build join.seb URL; include name so the server can pre-register the
                // student and point SEB straight at the content page, skipping join.html.
                // childId (kid-mode joins) rides along so the server can put the kid's
                // chosen avatar on the class roster — without it the roll call and the
                // class page fall back to initials.
                // deviceId identifies the paired device: combined with the server-side
                // authorisation the kid dashboard's class-launch call minted, it makes this
                // scheme join count as device-credentialed "in a class" — which is what
                // shields the class session from parent locks/schedules (class precedence).
                NSURLComponents *configComponents = [NSURLComponents componentsWithString:
                    [NSString stringWithFormat:@"https://blinkered.com.au/api/class/%@/join.seb", code]];
                if (studentName.length > 0) {
                    NSMutableArray<NSURLQueryItem *> *queryItems =
                        [NSMutableArray arrayWithObject:[NSURLQueryItem queryItemWithName:@"name" value:studentName]];
                    if (childId.length > 0) {
                        [queryItems addObject:[NSURLQueryItem queryItemWithName:@"childId" value:childId]];
                    }
                    if (deviceId.length > 0) {
                        [queryItems addObject:[NSURLQueryItem queryItemWithName:@"deviceId" value:deviceId]];
                    }
                    configComponents.queryItems = queryItems;
                }
                NSURL *configURL = configComponents.URL;
                DDLogInfo(@"blinkered://join received for code %@, loading %@", code, configURL.absoluteString);
                _openingSettings = YES;
                _openedURL = YES;
                // This focus/class session was launched from an existing web tab (the kid's
                // student dashboard, or a guest's join page) that we return to on exit. Do NOT let
                // applicationWillTerminateProceed open a fresh student.html tab — that both
                // duplicates the tab and, being new, loses the kid's in-tab session so it re-asks
                // for the PIN. (The blinkeredWebReturn bridge message is unreliable here — it lands
                // on a different browser instance than the terminate handler checks — so set the
                // skip flag directly.) The originating tab restores itself on return.
                _blinkeredSkipTerminateReturn = YES;
                // Cover the desktop before the config download starts (launch cleanup #2).
                [self blinkeredEarlyCoverScreens];
                [self.browserController openConfigFromSEBURL:configURL];
            }
        } else if ([url.host isEqualToString:@"savepair"]) {
            [self blinkeredHandleSavePair:url];
        }
    } else {
        if (url && !_openingSettings) {
            // If we have any URL, we try to download and open (conditionally) a .seb file
            // hopefully linked by this URL (also supporting redirections and authentification)
            _openingSettings = YES;
            _openedURL = YES;
            // A Blinkered parent-lock / home session (the agent opens blinkered-home-session.seb)
            // runs while the kid's student.html tab is still open in the default browser. Return to
            // THAT tab on exit instead of opening a duplicate — same reliable static-flag approach
            // as the focus/class join path. (The previous web-side suppression via studentSessionActive
            // was removed in web v0.9.299 and never reliably reached the terminate handler anyway.)
            if ([url.lastPathComponent containsString:@"home-session"] ||
                [url.absoluteString containsString:@"sethomesession"] ||
                [url.absoluteString containsString:@"/home/"]) {
                _blinkeredSkipTerminateReturn = YES;
            }
            DDLogInfo(@"openURLs event: Loading .seb settings file with URL %@", url.absoluteString);
            // Cover the desktop before the config download starts (launch cleanup #2).
            [self blinkeredEarlyCoverScreens];
            [self.browserController openConfigFromSEBURL:url];
        }
    }
}


- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    DDLogDebug(@"%s", __FUNCTION__);
    NSApp.presentationOptions |= (NSApplicationPresentationDisableForceQuit | NSApplicationPresentationHideDock);

    // Paired-device agent self-heal (deferred 20s, background queue — never on the launch path).
    // Covers registrations wiped by macOS updates; no-op when the agent is loaded. See the method.
    [self blinkeredScheduleAgentHealthCheck];
    
    NSArray <NSString *> *libraryDirs = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory,
                                                              NSLocalDomainMask | NSUserDomainMask,
                                                              YES);
    NSFileManager *fileManager= [NSFileManager defaultManager];

    for (NSString *libraryDir in libraryDirs) {
        BOOL isDir;
        NSString *keyBindingsFilePath = [libraryDir stringByAppendingPathComponent:KeyBindingsPath];
        if ([fileManager fileExistsAtPath:keyBindingsFilePath isDirectory:&isDir]) {
            DDLogError(@"Cocoa Text System key bindings file detected: at path %@", keyBindingsFilePath);
            NSAlert *modalAlert = [self newAlert];
            [modalAlert setMessageText:NSLocalizedString(@"Custom Key Binding Detected", @"")];
            [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"%@ doesn't allow to use custom key bindings. Please delete or rename the file at the path %@ and restart %@", @""), SEBShortAppName, keyBindingsFilePath, SEBShortAppName]];
            [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
            [modalAlert setAlertStyle:NSAlertStyleCritical];
            void (^keyBindingDetectedHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                [self removeAlertWindow:modalAlert.window];
                [self requestedExit:nil];
            };
            [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))keyBindingDetectedHandler];
            return;
        }
    }
    
    // Check if the font download alert was triggered from a web page
    // and SEB didn't had Accessibility permissions
    // and therefore was terminated to prevent a modal lock
    if (@available(macOS 10.9, *)) {
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        if ([preferences persistedSecureBoolForKey:fontDownloadAttemptedKey]) {
            
            NSDictionary *options = @{(__bridge id)
                                      kAXTrustedCheckOptionPrompt : @YES};
            // Check if we're trusted - and the option means "Prompt the user
            // to trust this app in System Preferences."
            NSAlert *modalAlert = nil;
            void (^accessibilityPermissionsAlertOK)(NSModalResponse) = ^void (NSModalResponse answer) {
                [self removeAlertWindow:modalAlert.window];
                [preferences setPersistedSecureBool:NO forKey:fontDownloadAttemptedKey];
                [preferences setPersistedSecureObject:@"" forKey:fontDownloadAttemptedOnPageTitleKey];
                [preferences setPersistedSecureObject:@"" forKey:fontDownloadAttemptedOnPageURLOrPlaceholderKey];
                [self applicationDidFinishLaunchingProceed];
            };
            if (!AXIsProcessTrustedWithOptions((CFDictionaryRef)options)) {
                modalAlert = [self newAlert];
                [modalAlert setMessageText:NSLocalizedString(@"Accessibility Permissions Required", @"")];
                [modalAlert setInformativeText:[NSString stringWithFormat:@"%@\n\n%@", [NSString stringWithFormat:NSLocalizedString(@"%@ needs Accessibility permissions to close the font download dialog displayed when a webpage tries to use a font not installed on your Mac. Grant access to %@ in Security & Privacy located in System Settings.", @""), SEBShortAppName, SEBFullAppNameClassic], [NSString stringWithFormat:NSLocalizedString(@"If you don't grant access to %@, you cannot use such webpages. Last time %@ was running, the webpage with the title '%@' (%@) tried to download a font.", @""), SEBShortAppName, SEBShortAppName, [preferences persistedSecureObjectForKey:fontDownloadAttemptedOnPageTitleKey], [preferences persistedSecureObjectForKey:fontDownloadAttemptedOnPageURLOrPlaceholderKey]]]];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                [modalAlert setAlertStyle:NSAlertStyleCritical];
                [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow
                  completionHandler:(void (^)(NSModalResponse answer))accessibilityPermissionsAlertOK];
            } else {
                accessibilityPermissionsAlertOK(NSModalResponseOK);
            }
        }
    }
    
    // No launch splash — Blinkered goes straight into its session for the fastest possible start
    // (the old 10-second About/splash was inherited upstream SEB behaviour, not needed). The black
    // covers still hide the desktop during load, so there's no desktop flash; the About window is
    // on-demand only (menu → About Blinkered).
    _alternateKeyPressed = [self alternateKeyCheck];
    if (_alternateKeyPressed == NO && (_openingSettings || _openedURL)) {
        [self blinkeredEarlyCoverScreens];
    }

    // After a drag-install the Blinkered.dmg is left mounted with its Finder window open.
    // Eject it now (which also closes that window) for a tidy first launch.
    [self blinkeredEjectInstallerDMG];

    // Blinkered: initialise Sparkle auto-updater. Self is the delegate so we can
    // intercept didFindValidUpdate / didNotFindUpdate on bare launches.
    self.updaterController = [[SPUStandardUpdaterController alloc]
        initWithStartingUpdater:YES updaterDelegate:self userDriverDelegate:nil];

    // Bottom-edge reveal: when a 🪟 site (e.g. Office) is open in a separate window
    // covering the content page, pushing the cursor to the very bottom of the screen
    // brings the main window (with its tab bar) back to the front.
    [self startMainWindowBottomEdgeReveal];

    // Blinkered: if a .seb file was already queued (Finder double-click on .seb), proceed
    // immediately. Otherwise wait 0.3 s for a blinkered:// URL scheme event to arrive.
    // If none comes it is a bare double-click — redirect to the web app and quit cleanly.
    if (_openingSettings || _openedURL) {
        if (_blinkeredSavePair) {
            // Credentials saved by openURLs:. FORCE-(re)start the background agent NOW, before we quit —
            // this is what makes a freshly paired device immediately lockable. Two cases it covers:
            //   (a) FIRST pairing: no agent is running yet, so without this the device can't be locked
            //       until the app is next launched (savepair quits right after) — parents hit "nothing
            //       happens when I lock."
            //   (b) RE-pair after the parent REMOVED the device: handleRemoval() in the agent latches a
            //       "deactivated" flag and deletes agent.json, but the process keeps running. Re-pairing
            //       writes new creds yet the stale agent ignores them (and every lock) until it restarts.
            // blinkeredInstallLegacyLaunchAgent always does bootout+bootstrap (a real restart) — NOT
            // the idempotent health-check, which would no-op a "running but stale" agent. So the very
            // next poll runs on fresh creds with a clean state and picks up any pending lock.
            [self blinkeredInstallLegacyLaunchAgent];
            // Right after pairing (parent present on the kid's standard account) is the one reliable
            // moment to finish setup. In Enforced, that means guiding the account change — the .pkg has
            // already installed the updater daemon, so the auto-update card wouldn't show anyway; this
            // card takes that slot. Both quit when finished/dismissed; if neither applies, quit now.
            if (![self blinkeredShowEnforcedSetupThenQuit] &&
                ![self blinkeredShowAutoUpdateSetupThenQuit]) {
                DDLogInfo(@"Blinkered: savepair complete — quitting");
                quittingMyself = YES;
                [NSApp performSelector:@selector(terminate:) withObject:self afterDelay:0.5];
            }
        } else {
            [self applicationDidFinishLaunchingProceed];
        }
    } else {
        [self performSelector:@selector(blinkeredCheckBareLaunch) withObject:nil afterDelay:0.3];
    }
}

// Set when a bare launch is waiting on a Sparkle update check before redirecting.
// Cleared by the Sparkle delegate callbacks or blinkeredDoBareLaunchRedirect.
static BOOL _blinkeredPendingRedirect = NO;

// Set when the app was launched via blinkered://savepair — skip normal session startup.
static BOOL _blinkeredSavePair = NO;

// Set when the return is already handled, so applicationWillTerminateProceed must NOT open a
// student.html tab on quit:
//   • blinkeredDoBareLaunchRedirect already opened the right destination, then quits; and
//   • a blinkered://join focus/class session was launched from an existing web tab we return to
//     (a new tab there duplicates it AND loses the kid's session, re-prompting the PIN).
static BOOL _blinkeredSkipTerminateReturn = NO;

// First-run guided setup (Accessibility) — shown at most once per launch on a bare launch.
static BlinkeredOnboardingController *_blinkeredOnboarding = nil;
static BOOL _blinkeredOnboardingShown = NO;

// Pixels reserved at the TOP of full-window site windows (Office etc.) so the home page's
// always-visible browser tab bar shows above them. Set by the home page via the bridge
// (setTopInset); 0 = no reservation (e.g. the class page, which has no top tab bar).
CGFloat blinkeredTopInset = 0;

// After a Sparkle update the running background agent is still the OLD binary
// (launchd doesn't restart it when the app bundle is replaced), which leaves the
// next lock in a broken state until the device is unlocked + relaunched. A bare
// launch is exactly what Sparkle performs right after installing an update, and
// it's a safe point (no session active) to reinstall the LaunchAgent so it runs
// the current agent binary.
- (void)blinkeredRefreshAgentIfPaired {
    NSArray *appSupportDirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[appSupportDirs firstObject]
        stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:agentJson]) {
        DDLogInfo(@"Blinkered: bare launch — ensuring background agent is installed + running");
        // reportRepair:YES — a paired device whose agent was missing (the FAST recovery path, e.g.
        // a kid opening Blinkered) now tells the parent too, not just the slow health check.
        [self blinkeredInstallLaunchAgentReportRepair:YES];
        // P1-2: on a paired launch, Cooperative must have NO root component. De-register any SMAppService
        // updater and SKIP the daemon-plist refresh (which would re-register it). Enforced/legacy keep
        // today's behavior — refresh re-registers only an already-enabled SMAppService daemon (no-op for a
        // pkg /Library/LaunchDaemons job, which the app never touches).
        // R1d (docs/UPDATER_ROOT_EXEC_FIX_PLAN.md §4): RETIRE the SMAppService updater on EVERY paired
        // launch, in ALL modes — not only Cooperative. The SMAppService variant runs an in-bundle
        // BundleProgram, which cannot take R1's out-of-bundle fix; the pkg /Library/LaunchDaemons daemon
        // (which R1c migrates out-of-bundle) is the only root updater we keep. The retire helper
        // early-returns when the pkg plist is present (never touches the Enforced mechanism) and only ever
        // de-registers a genuine app-registered SMAppService daemon — safe unconditionally. The old
        // else-branch (blinkeredRefreshUpdaterDaemonPlistIfNeeded) RE-REGISTERED the daemon being retired
        // once per build; it is deleted.
        [self blinkeredRetireSMAppServiceUpdater];
    }
}


// Keeps the auto-update setup card alive while shown. Base type (not the 13-only subclass) so the
// file-scope declaration has no availability constraint; assigned only inside @available blocks.
static NSWindowController *_blinkeredAutoUpdateController = nil;

// Same, for the Enforced assisted-manual setup card.
static NSWindowController *_blinkeredEnforcedSetupController = nil;

// Show the one-time "Secure this device" auto-update card (parent enables the root updater daemon via
// SMAppService, entering an admin password once). Returns YES if the card was shown — it QUITS the app on
// finish/dismiss; NO if not applicable (already enabled, or macOS < 13), so the caller quits itself. This
// is the post-pairing entry point. See docs/PARENT_SETUP_REGISTRATION.md.
// P1-2: the onboarding mode persisted in agent.json at pairing. Returns @"cooperative", @"enforced", or nil
// (LEGACY device paired before mode existed). A nil mode means "preserve today's behavior" — callers must
// NOT gate the card or de-register anything on nil; act only when the mode is EXPLICITLY known.
- (NSString *)blinkeredPersistedMode {
    NSArray *appSupportDirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[appSupportDirs firstObject] stringByAppendingPathComponent:@"Blinkered"]
        stringByAppendingPathComponent:@"agent.json"];
    NSData *data = [NSData dataWithContentsOfFile:agentJson];
    if (!data) return nil;
    NSDictionary *creds = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![creds isKindOfClass:[NSDictionary class]]) return nil;
    id m = creds[@"mode"];
    return [m isKindOfClass:[NSString class]] ? m : nil;
}

// P1-2: guarantee NO root component in Cooperative. If an SMAppService updater daemon is somehow registered
// (e.g. a device promoted to Enforced then re-paired Cooperative, or a stray earlier registration), de-register
// it. ONLY the SMAppService-registered variant: SMAppService's unregister acts on the app-bundled
// BundleProgram registration, NOT on a pkg /Library/LaunchDaemons job — so this can NEVER remove the Enforced
// mechanism the app didn't install. No-ops unless the SMAppService updater is actually registered.
- (void)blinkeredRetireSMAppServiceUpdater {
    if (@available(macOS 13.0, *)) {
        // NEVER touch a pkg /Library/LaunchDaemons job — that is Enforced's mechanism, which the app didn't
        // install and mustn't remove. It shares our Label (app.blinkered.updater), so SMAppService.status
        // REPORTS it as Enabled and unregisterAndReturnError: would target it and return an error
        // ("lacks required entitlement"). Verified via E2E on a pkg install.
        //
        // CORRECTED — this used to say the call "would FAIL", and that word did real damage: the agent's
        // twin in blinkeredInstallLegacyLaunchAgent discarded its NSError on the strength of it and
        // shipped a call that took a family Mac off the air. THE ERROR IS NOT PROTECTIVE. Measured: on
        // the agent's same-Label collision the call returns error 144 AND STILL disables the item in
        // BTM, boots out the job and kills the process. Treat a non-nil NSError here as "it may well
        // have happened anyway", never as "nothing happened". The pkg-plist guard below — not the
        // error — is what makes this safe. So if the pkg plist exists, this is an Enforced device: skip entirely. (An
        // Enforced→Cooperative switch removes the root daemon via the privileged path, not here.) The
        // remaining path — no pkg plist, but the SMAppService daemon Enabled — is a genuine app-registered
        // SMAppService updater we DID register (e.g. via the "Secure this device" card), which we can unregister.
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/LaunchDaemons/app.blinkered.updater.plist"]) {
            DDLogInfo(@"Blinkered: Cooperative — pkg updater LaunchDaemon present; leaving it (Enforced mechanism, not ours to remove)");
            return;
        }
        SMAppService *svc = [SMAppService daemonServiceWithPlistName:@"app.blinkered.updater.plist"];
        SMAppServiceStatus st = svc.status;
        if (st == SMAppServiceStatusEnabled || st == SMAppServiceStatusRequiresApproval) {
            NSError *err = nil;
            BOOL ok = [svc unregisterAndReturnError:&err];
            DDLogInfo(@"Blinkered: Cooperative mode — de-registered SMAppService updater (ok=%d was-status=%ld err=%@)",
                      ok, (long)st, err.localizedDescription);
        }
    }
}

- (BOOL)blinkeredShowAutoUpdateSetupThenQuit {
    if (@available(macOS 13.0, *)) {
        // P1-2: Cooperative = NO root component. Never construct/show the card or register the SMAppService
        // updater in Cooperative. (A nil/absent mode = legacy device -> preserve today's behavior; do NOT
        // gate on nil.) Also tear down any stray SMAppService registration as belt-and-braces.
        if ([[self blinkeredPersistedMode] isEqualToString:@"cooperative"]) {
            [self blinkeredRetireSMAppServiceUpdater];
            DDLogInfo(@"Blinkered: Cooperative mode — suppressing the auto-update card (no root component)");
            return NO;
        }
        if (blinkeredUpdaterDaemonInstalled()) return NO;   // already set up (pkg LaunchDaemon or SMAppService) — no card
        BlinkeredAutoUpdateController *ctrl = [[BlinkeredAutoUpdateController alloc] init];
        __weak typeof(self) ws = self;
        ctrl.onFinish = ^{
            _blinkeredAutoUpdateController = nil;
            ws.quittingMyself = YES;
            [NSApp performSelector:@selector(terminate:) withObject:NSApp afterDelay:0.2];
        };
        [ctrl showCard];
        _blinkeredAutoUpdateController = ctrl;
        return YES;
    }
    return NO;
}

// Enforced only: guide the parent through the account change, then VERIFY it read-only. Returns YES if the
// card was shown (caller must not quit — the card's onFinish quits instead).
//
// Hard-gated: shows ONLY when the persisted mode is exactly "enforced". Cooperative and legacy (nil/absent
// mode) never see it — a legacy device has made no Enforced promise, so nagging it to demote a child would
// be inventing a requirement the parent never agreed to.
- (BOOL)blinkeredShowEnforcedSetupThenQuit {
    if (![[self blinkeredPersistedMode] isEqualToString:@"enforced"]) return NO;
    // Already verified (child is Standard) → nothing to guide; never nag a finished device.
    // -1 (unknown) also returns NO: we act only on a POSITIVE observation that the child is still admin,
    // so a failed check can't invent a setup step.
    if (blinkeredRunningUserIsAdmin() != 1) {
        DDLogInfo(@"Blinkered: Enforced — no setup card (running user is not a confirmed admin)");
        return NO;
    }
    BlinkeredEnforcedSetupController *ctrl = [[BlinkeredEnforcedSetupController alloc] init];
    __weak typeof(self) ws = self;
    ctrl.onFinish = ^{
        _blinkeredEnforcedSetupController = nil;
        ws.quittingMyself = YES;
        [NSApp performSelector:@selector(terminate:) withObject:NSApp afterDelay:0.2];
    };
    [ctrl showCard];
    _blinkeredEnforcedSetupController = ctrl;
    DDLogInfo(@"Blinkered: Enforced mode — showing the assisted-manual setup card (guide + verify only)");
    return YES;
}

// Re-open the Enforced setup card on demand (e.g. the locked-session ⋯ menu). Does NOT quit.
- (void)blinkeredShowEnforcedSetup {
    if (![[self blinkeredPersistedMode] isEqualToString:@"enforced"]) {
        DDLogInfo(@"Blinkered: not Enforced — refusing Enforced setup card re-invoke");
        return;
    }
    BlinkeredEnforcedSetupController *ctrl = [[BlinkeredEnforcedSetupController alloc] init];
    ctrl.onFinish = ^{ _blinkeredEnforcedSetupController = nil; };
    ctrl.elevatedLevel = YES;   // re-invoked over a kiosk lock — must float above the lock windows
    [ctrl showCard];
    _blinkeredEnforcedSetupController = ctrl;
}

// Re-open the auto-update setup card on demand (e.g. from the locked-session menu). Does NOT quit.
- (void)blinkeredShowAutoUpdateSetup {
    if (@available(macOS 13.0, *)) {
        // P1-2: never offer the root-daemon card in Cooperative, even from the locked-session menu. (nil mode
        // = legacy -> unchanged; only Cooperative suppresses.)
        if ([[self blinkeredPersistedMode] isEqualToString:@"cooperative"]) {
            [self blinkeredRetireSMAppServiceUpdater];
            DDLogInfo(@"Blinkered: Cooperative mode — refusing locked-session auto-update card re-invoke");
            return;
        }
        BlinkeredAutoUpdateController *ctrl = [[BlinkeredAutoUpdateController alloc] init];
        ctrl.onFinish = ^{ _blinkeredAutoUpdateController = nil; };
        [ctrl showCard];
        _blinkeredAutoUpdateController = ctrl;
    }
}

// A macOS update can wipe the SMAppService background-item registration entirely (seen 10 Jul 2026:
// after an OS update + reboot, launchd had NO record of app.blinkered.agent — the device silently
// lost locking until Blinkered happened to be bare-launched). The bare-launch refresh above can't
// cover that: nobody bare-launches Blinkered in normal use, but kids DO open sessions (a fallback
// Focus, a class join). So on EVERY launch of a paired device, verify a little while after startup —
// well off the session-launch critical path, on a background queue — that launchd actually has the
// agent, and re-register if not. When the agent is loaded (the overwhelmingly common case, since the
// agent itself usually launched us) this is a single ~50ms launchctl check and zero churn.
// URL of the kid dashboard, with THIS device's token when paired. Passing dtok forces /student.html
// to consume it into localStorage on load, so the kid sees the correct persona for THIS device —
// not whatever stale token earlier pairing tests left in the default browser.
- (NSString *)blinkeredStudentDashboardURLString {
    NSArray *appSupportDirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[appSupportDirs firstObject]
        stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    NSString *dtok = nil;
    NSData *data = [NSData dataWithContentsOfFile:agentJson];
    if (data) {
        NSDictionary *creds = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if ([creds isKindOfClass:[NSDictionary class]] && [creds[@"token"] isKindOfClass:[NSString class]]) {
            dtok = creds[@"token"];
        }
    }
    if (dtok.length) {
        NSCharacterSet *q = [NSCharacterSet URLQueryAllowedCharacterSet];
        return [NSString stringWithFormat:@"https://blinkered.com.au/student.html?dtok=%@",
                [dtok stringByAddingPercentEncodingWithAllowedCharacters:q]];
    }
    return @"https://blinkered.com.au/student.html";
}

- (void)blinkeredScheduleAgentHealthCheck {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSArray *appSupportDirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString *agentJson = [[[appSupportDirs firstObject]
            stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
        if (![[NSFileManager defaultManager] fileExistsAtPath:agentJson]) return;   // not paired
        // F6 — NEVER repair from the health check while a lock is live.
        //
        // The plan argued this intersection was narrow, "since an unregistered device generally cannot
        // be locked at all". The measurement falsifies that: Poppy's Mac was running, print exit 0,
        // marker present — submitted and fully lockable. And with C11, launcherCurrent is false on
        // EVERY deployed Mac, so on migration day this fires on every one of them.
        //
        // What it would do: 20 s into a locked session the repair boots the agent out and back; the
        // restarted agent's lastSessionId is nil, so the live lock takes the cold-launch branch, which
        // runs terminateRunningBlinkeredAndWait — SIGKILL on the kiosk a child is using — and then
        // relaunches. Roughly 10-30 s unlocked, once per device, and most likely DURING a lock,
        // because on a kid's Mac a lock is what launches the app in the first place.
        //
        // Deferring costs nothing: the repair runs at the next unlocked launch, and the pairing and
        // bare-launch paths still repair immediately. This is a different axis from C10's latch, which
        // stays: C10 bounds how OFTEN, this bounds WHEN.
        // C13 — and it must require a LIVE AGENT. Both files the guard reads are cleared only by a
        // running agent (measured: zero removal sites for last-lock.json in Classes/, seven in the
        // agent). So on a device whose agent has DIED — the entire population this workstream exists
        // for — the guard would latch ON permanently and this health check, the only repair path a
        // kid's Mac reaches without someone opening the app, would never repair again.
        //
        // It also fires hardest where its own rationale does not apply: the harm needs a RESTARTED
        // AGENT to find a lock to cold-launch, and there is no agent to restart. Pre-F6 that device's
        // wasRunning was NO and the repair fired harmlessly. Without this term F6 blocks precisely the
        // harmless case and permits nothing new.
        //
        // F6's actual purpose — migration day, agent alive, lock live — is preserved exactly.
        // H3 — Unknown must DEFER here, not repair. Falling to "not alive" would let an unanswerable
        // ps authorise the bootout, restart, cold-launch and SIGKILL that C13 exists to prevent.
        NSString *agentBin = [[NSBundle mainBundle].bundlePath
            stringByAppendingPathComponent:@"Contents/MacOS/BlinkeredAgent"];
        BlinkeredAgentLiveness agentLiveness = [self blinkeredAgentProcessLiveness:agentBin];
        if (agentLiveness != BlinkeredAgentLivenessDead && [self blinkeredLockSessionLive]) {
            DDLogWarn(@"Blinkered: agent health-check repair DEFERRED — a lock is live and the agent is "
                      @"%@ (liveness %ld), so repairing could restart it, cold-launch the live lock and "
                      @"SIGKILL the running kiosk. Will repair on the next unlocked launch.",
                      agentLiveness == BlinkeredAgentLivenessAlive ? @"running" : @"of unknown state",
                      (long)agentLiveness);
            return;
        }
        // Idempotent + reports if it actually had to repair a missing agent (see the install method).
        [self blinkeredInstallLaunchAgentReportRepair:YES];
        // P1-2: universal-launch belt-and-braces — if Cooperative, ensure no SMAppService root component
        // survives (covers session launches that don't hit the bare-launch refresh above). nil/enforced = no-op.
        if ([[self blinkeredPersistedMode] isEqualToString:@"cooperative"]) {
            [self blinkeredRetireSMAppServiceUpdater];
        }
    });
}

#pragma mark - Blinkered launch-time credential hygiene (SEB_QUIT_HARDENING_PLAN §3.4, §5 step 3)

// Clear the OTHER session type's quit credentials at launch, before the browser opens.
//
// WHY THIS IS ITS OWN STEP. These two files are quit credentials, and each session type used to
// rely on the *other* type's URL interceptor having deleted its file. That coupling produced a
// live escalation reachable with NO ATTACKER AT ALL — just a network retry (§1.6 items 1–2):
//
//   • A home lock following an earlier class inherits a stale class_quit_hash.txt. SEBController
//     prefers that file over the config's hashedQuitPassword, so the native quit dialog validates
//     THE OLD TEACHER'S hash rather than the parent's Master Exit Code — and isHomeQuit is false,
//     so the brute-force throttle never engages either.
//   • A class session following a home lock inherits a stale home_session.json, whose own comment
//     warns a leftover "would fire home behaviour inside an exam", and which silently refuses the
//     teacher's setQuitPassword push.
//
// The obvious fix — have the interceptors delete unconditionally — is NOT available: an
// unconditional delete of home_session.json is exactly the primitive that made /seb-setquit an
// escape. So ownership moves here, to launch, where it covers home lock, home Focus, class, static
// and offline-cover in one place and is not reachable from page content at all.
//
// The rule is "never delete what THIS session needs", so it is safe to run unconditionally:
//   class session  → drop the home credentials
//   anything else  → drop the class credentials
// An offline-cover session (agent-minted config, startURL blinkered-offlinecover://) is not a class
// session, so it correctly keeps the home_session.json the agent wrote for it and drops any stale
// class hash.
- (void)blinkeredClearStaleSessionCredentials
{
    NSString *startURL = [[NSUserDefaults standardUserDefaults] secureStringForKey:@"org_safeexambrowser_SEB_startURL"];
    BOOL isClassSession = startURL != nil && [startURL rangeOfString:@"/seb-setsession"].location != NSNotFound;

    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir = [appSupport stringByAppendingPathComponent:@"Blinkered"];
    NSFileManager *fm = [NSFileManager defaultManager];

    NSArray<NSString *> *stale = isClassSession
        ? @[ @"home_session.json" ]
        : @[ @"class_quit_hash.txt", @"class_session.json" ];

    for (NSString *name in stale) {
        NSString *path = [dir stringByAppendingPathComponent:name];
        if ([fm fileExistsAtPath:path]) {
            NSError *error = nil;
            if ([fm removeItemAtPath:path error:&error]) {
                DDLogInfo(@"Blinkered: cleared stale %@ at launch (%@ session) — it belongs to the other session type",
                          name, isClassSession ? @"class" : @"home/focus/static");
            } else {
                // Loud, because a surviving stale credential means the native quit dialog may be
                // validating the wrong password for the whole session.
                DDLogError(@"Blinkered SECURITY: could NOT clear stale %@ at launch (%@) — the native quit "
                           @"dialog may validate the wrong credential this session", name, error.localizedDescription);
            }
        }
    }
}

// [§8.9] Make the degraded state VISIBLE. §3.3 permits a start-URL write to be skipped (refused, or
// a load that never happened), and a home lock with no home_session.json is invisible to BOTH the
// quit path and the watchdog: blinkeredHomeSessionInfo keys on that file, and the agent relaunches
// only when the app is NOT running — a degraded-but-running app is neither repaired nor reported.
// That is the same invisibility class as the blank-locked-window brick this plan's history is full
// of, so it gets converted into a signal.
//
// Deliberately delayed: the file is written by the start-URL interceptor as the shell loads, and on
// a slow or retried load that can be tens of seconds after launch. Checking at launch would report
// every healthy lock.
//
// [FIX2-G1 §5] NOW PERIODIC, not one-shot. The write guard refuses to RE-CREATE a home_session.json
// the agent deleted, and it cannot tell that deletion from a kid's. So the guard's one named
// regression is that a kid who deletes the file mid-session gets a DURABLE degraded lock instead of
// one silently repaired by the next start-URL navigation. A launch+60s check never sees that. This
// is the smaller of the two remedies the review weighed (the other being to cache the identity in
// an ivar and repair from memory); it detects and REPORTS rather than repairing, so the server —
// and through it a parent — learns the device needs a remote unlock.
//
// EDGE-TRIGGERED, not level-triggered: the security event POSTs once per missing EPISODE, not once
// per tick. A device that is genuinely degraded for an hour must not POST every two minutes, and a
// repair followed by a second deletion must still be reported.
//
// DEBOUNCED over two consecutive ticks, which is not a nicety — it is what stops this reporting
// every ordinary unlock. A remote unlock deletes home_session.json and THEN force-quits at an 8 s
// grace, so during a NORMAL unlock the file is legitimately absent while the app is still running.
// A tick landing in that window would POST home_session_missing for a healthy device. The app
// cannot survive two ticks 120 s apart inside an 8 s grace, so requiring the state to persist
// separates the durable degraded lock from the unlock window without having to distinguish them
// by any other means. The cost is detection latency of about three minutes, which is the right
// trade against crying wolf on every unlock.
//
// Re-checks blinkeredIsHomeLockSession every tick, and captures a generation, so a restart into a
// non-home session stops the timer and a restart into another home session does not leave two
// running.
//
// [R2 F3] REPORTED MEANS DELIVERED, NOT DISPATCHED. The first version set the per-episode flag on
// the line after -blinkeredReportSecurityEvent:, which is dataTaskWithRequest: + resume with no
// completion handler. On an OFFLINE device — the entire population this workstream exists for —
// the POST died in the network stack, the flag latched, and the episode was never reported again
// even after connectivity returned. The mitigation that pays for this guard's deliberate
// regression was mute exactly where it was needed. The flag is now set from a 2xx and nowhere
// else, so every later tick retries until the server has actually heard.
//
// The local record and the server record are separate flags on purpose: the DDLogError is written
// once per episode (a device that can never report must not spam its own log every two minutes),
// while the POST is retried until delivered.
//
// [R2 F7] ALL STATE BELOW IS MAIN-QUEUE CONFINED. Three writers now exist — the scheduler, the
// timer, and the POST's completion handler — and the latch in SEBAbstractWebView was given
// @synchronized on the stated principle that state whose failure mode is "a parent cannot exit the
// device" should not rest on a threading property of two subsystems. The same principle applies
// here. The file read stays on the utility queue; the predicate, the state and the re-arm hop to
// main, which also restores the pre-PR property that secureStringForKey: is read on main only.
static const NSTimeInterval kBlinkeredHomeSessionSanityFirstCheck = 60;
static const NSTimeInterval kBlinkeredHomeSessionSanityInterval   = 120;
static const NSUInteger kBlinkeredHomeSessionSanityMissingTicksToReport = 2;
// File-scope, matching _blinkeredOfflinePanelShowing and _blinkeredTeardownStarted above: there is
// one SEBController per process and one home-session file per process, so per-instance state would
// be a distinction without a difference.
static NSUInteger _blinkeredHomeSessionSanityGeneration = 0;
static NSUInteger _blinkeredHomeSessionSanityMissingStreak = 0;
static BOOL _blinkeredHomeSessionSanityLogged = NO;     // local record written, once per episode
static BOOL _blinkeredHomeSessionSanityReported = NO;   // server ACKed 2xx, once per episode
static BOOL _blinkeredHomeSessionSanityReportInFlight = NO;

- (void)blinkeredScheduleHomeSessionSanityCheck
{
    // Bump first, unconditionally: a restart into a NON-home session must also orphan the timer
    // that a previous home session left running.
    _blinkeredHomeSessionSanityGeneration += 1;
    _blinkeredHomeSessionSanityMissingStreak = 0;
    _blinkeredHomeSessionSanityLogged = NO;
    _blinkeredHomeSessionSanityReported = NO;
    _blinkeredHomeSessionSanityReportInFlight = NO;
    if (![SEBBrowserWindow blinkeredIsHomeLockSession]) {
        return;   // only home locks are supposed to have this file
    }
    [self blinkeredArmHomeSessionSanityCheckAfter:kBlinkeredHomeSessionSanityFirstCheck
                                       generation:_blinkeredHomeSessionSanityGeneration];
}

- (void)blinkeredArmHomeSessionSanityCheckAfter:(NSTimeInterval)delay generation:(NSUInteger)generation
{
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        typeof(self) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        // The only work done off-main: read the file. Everything that follows touches shared state.
        BOOL missing = ([strongSelf blinkeredHomeSessionInfo] == nil);
        dispatch_async(dispatch_get_main_queue(), ^{
            typeof(self) mainSelf = weakSelf;
            if (!mainSelf || _blinkeredHomeSessionSanityGeneration != generation) {
                return;   // app gone, or a newer session superseded this timer
            }
            if (![SEBBrowserWindow blinkeredIsHomeLockSession]) {
                return;   // no longer a home lock — nothing to check, and nothing to re-arm
            }
            [mainSelf blinkeredHomeSessionSanityTickMissing:missing generation:generation];
            [mainSelf blinkeredArmHomeSessionSanityCheckAfter:kBlinkeredHomeSessionSanityInterval
                                                   generation:generation];
        });
    });
}

// One tick's state transition. Main queue only.
- (void)blinkeredHomeSessionSanityTickMissing:(BOOL)missing generation:(NSUInteger)generation
{
    if (!missing) {
        if (_blinkeredHomeSessionSanityLogged) {
            DDLogInfo(@"Blinkered: home_session.json is present again — the degraded home lock was repaired");
        }
        _blinkeredHomeSessionSanityMissingStreak = 0;
        _blinkeredHomeSessionSanityLogged = NO;
        _blinkeredHomeSessionSanityReported = NO;
        return;
    }

    _blinkeredHomeSessionSanityMissingStreak += 1;
    if (_blinkeredHomeSessionSanityMissingStreak < kBlinkeredHomeSessionSanityMissingTicksToReport) {
        return;   // still inside the debounce — could be an ordinary unlock's 8 s grace
    }

    if (!_blinkeredHomeSessionSanityLogged) {
        DDLogError(@"Blinkered SECURITY: home lock session running with NO home_session.json across "
                   @"%lu consecutive checks — the start-URL write did not happen, or the file was "
                   @"deleted mid-session. The master-code bridge exit is REFUSED, no parent-exit "
                   @"marker can be written, the quit-dialog throttle and the normalisation-tolerant "
                   @"exit-code acceptance are disarmed, and setQuitPassword's home refusal is off.",
                   (unsigned long)_blinkeredHomeSessionSanityMissingStreak);
        _blinkeredHomeSessionSanityLogged = YES;
    }

    // [R2 F3] Retry until the server has actually heard. The flag is set from the 2xx and nowhere
    // else, so an offline device reports the moment it is back rather than never.
    if (_blinkeredHomeSessionSanityReported || _blinkeredHomeSessionSanityReportInFlight) {
        return;
    }
    _blinkeredHomeSessionSanityReportInFlight = YES;
    // The report path reads creds from agent.json, which exists independently of
    // home_session.json — so a device in exactly this degraded state can still report it.
    [self blinkeredReportSecurityEvent:@"home_session_missing" completion:^(BOOL delivered) {
        dispatch_async(dispatch_get_main_queue(), ^{
            _blinkeredHomeSessionSanityReportInFlight = NO;
            if (_blinkeredHomeSessionSanityGeneration != generation) {
                return;   // a newer session owns this state now
            }
            if (delivered) {
                _blinkeredHomeSessionSanityReported = YES;
                DDLogInfo(@"Blinkered: home_session_missing accepted by the server");
            } else {
                DDLogWarn(@"Blinkered: home_session_missing NOT delivered — retrying on the next check. "
                          @"Until it lands, the parent has not been told this device is degraded.");
            }
        });
    }];
}

// Shared best-effort security-event POST. Device creds from agent.json.
- (void)blinkeredReportSecurityEvent:(NSString *)eventType {
    [self blinkeredReportSecurityEvent:eventType completion:nil];
}

// [R2 F3] The delivery-reporting variant. `completion` is called with YES only on a 2xx — every
// other outcome, including "there are no credentials to report with" and "the network is down", is
// NO. A caller that latches an edge-trigger on the result therefore latches on the server having
// heard, not on the request having been handed to NSURLSession.
//
// Note the log line: it says DISPATCHED, not "reported". The old wording claimed the action before
// the no-op was ruled out, which is this workstream's most-repeated lesson.
- (void)blinkeredReportSecurityEvent:(NSString *)eventType completion:(void (^)(BOOL delivered))completion {
    void (^done)(BOOL) = ^(BOOL delivered) { if (completion) completion(delivered); };
    NSArray *appSupportDirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[appSupportDirs firstObject]
        stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    NSData *credData = [NSData dataWithContentsOfFile:agentJson];
    NSDictionary *creds = credData ? [NSJSONSerialization JSONObjectWithData:credData options:0 error:nil] : nil;
    if (![creds isKindOfClass:[NSDictionary class]]) { done(NO); return; }
    NSString *devId = creds[@"id"], *devTok = creds[@"token"];
    NSString *server = [creds[@"server"] isKindOfClass:[NSString class]] ? creds[@"server"] : @"https://blinkered.com.au";
    if (![devId isKindOfClass:[NSString class]] || ![devTok isKindOfClass:[NSString class]]) { done(NO); return; }
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/home/devices/%@/security-event", server, devId]];
    if (!url) { done(NO); return; }
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{ @"token": devTok, @"type": eventType } options:0 error:nil];
    if (!req.HTTPBody) { done(NO); return; }
    [[[NSURLSession sharedSession] dataTaskWithRequest:req
                                    completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSInteger status = [response isKindOfClass:[NSHTTPURLResponse class]] ? ((NSHTTPURLResponse *)response).statusCode : 0;
        BOOL delivered = (error == nil && status >= 200 && status < 300);
        if (!delivered) {
            DDLogWarn(@"Blinkered: %@ POST did not land (status %ld, error %@)",
                      eventType, (long)status, error.localizedDescription ?: @"none");
        }
        done(delivered);
    }] resume];
    DDLogInfo(@"Blinkered: %@ dispatched to server", eventType);
}

// POST an agent_repaired security event so the parent learns the background helper was off and has
// been brought back (dashboard/push/email, deduped server-side). Reads device creds from agent.json.
- (void)blinkeredReportAgentRepaired {
    NSArray *appSupportDirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[appSupportDirs firstObject]
        stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    NSData *credData = [NSData dataWithContentsOfFile:agentJson];
    NSDictionary *creds = credData ? [NSJSONSerialization JSONObjectWithData:credData options:0 error:nil] : nil;
    if (![creds isKindOfClass:[NSDictionary class]]) return;
    NSString *devId = creds[@"id"], *devTok = creds[@"token"];
    NSString *server = [creds[@"server"] isKindOfClass:[NSString class]] ? creds[@"server"] : @"https://blinkered.com.au";
    if (![devId isKindOfClass:[NSString class]] || ![devTok isKindOfClass:[NSString class]]) return;
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/home/devices/%@/security-event", server, devId]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{ @"token": devTok, @"type": @"agent_repaired" } options:0 error:nil];
    [[[NSURLSession sharedSession] dataTaskWithRequest:req] resume];
    DDLogInfo(@"Blinkered: reported agent_repaired to server");
}

- (void)blinkeredShowOnboarding {
    DDLogInfo(@"Blinkered: Accessibility not granted on bare launch — showing guided setup");
    _blinkeredOnboarding = [[BlinkeredOnboardingController alloc] init];
    __weak typeof(self) ws = self;
    _blinkeredOnboarding.onFinish = ^{
        _blinkeredOnboarding = nil;
        // Continue the normal bare-launch flow (update check + redirect) now that the
        // user has finished or skipped setup. The "shown" flag prevents re-showing.
        [ws blinkeredCheckBareLaunch];
    };
    [_blinkeredOnboarding showOnboarding];
}

// A device is "paired" only if agent.json exists AND carries a usable id + token. A partial
// or empty file (e.g. a half-finished pairing) counts as unpaired, so the user is sent to the
// welcome screen rather than an empty student page.
- (BOOL)blinkeredIsPaired {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[dirs firstObject]
        stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    NSData *data = [NSData dataWithContentsOfFile:agentJson];
    if (!data) return NO;
    NSDictionary *creds = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return ([creds isKindOfClass:[NSDictionary class]] &&
            [creds[@"id"] isKindOfClass:[NSString class]] && [creds[@"id"] length] > 0 &&
            [creds[@"token"] isKindOfClass:[NSString class]] && [creds[@"token"] length] > 0);
}

// Eject any mounted Blinkered installer disk image so its Finder window doesn't linger after a
// drag-install. Never ejects the volume we're actually running from (i.e. if launched from the
// DMG itself rather than /Applications).
- (void)blinkeredEjectInstallerDMG {
    if ([[[NSBundle mainBundle] bundlePath] hasPrefix:@"/Volumes/"]) return;
    NSArray *vols = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/Volumes" error:nil];
    for (NSString *v in vols) {
        if ([v hasPrefix:@"Blinkered"]) {
            NSString *path = [@"/Volumes" stringByAppendingPathComponent:v];
            if ([[NSWorkspace sharedWorkspace] unmountAndEjectDeviceAtPath:path]) {
                DDLogInfo(@"Blinkered: ejected installer volume %@", v);
            }
        }
    }
}

- (void)blinkeredCheckBareLaunch {
    if (!_openingSettings && !_openedURL) {
        // Guided first-run setup: if Accessibility (required for the lockdown) isn't
        // granted yet, walk the user through enabling it before redirecting away.
        if (!AXIsProcessTrusted() && !_blinkeredOnboardingShown) {
            _blinkeredOnboardingShown = YES;
            [self blinkeredShowOnboarding];
            return;
        }
        // Unpaired devices just hand off to the welcome page and quit — no kiosk session is
        // coming, so there is nothing to update-gate. Redirect immediately: this is the
        // difference between a near-instant welcome and ~25s of splash + update-check wait.
        if (![self blinkeredIsPaired]) {
            DDLogInfo(@"Blinkered: bare launch (unpaired) — redirecting to welcome immediately");
            [self blinkeredDoBareLaunchRedirect];
            return;
        }
        // A paired device hands straight off to the student dashboard. We no longer run an in-app Sparkle
        // check here: the root updater DAEMON keeps the app current in the background (no admin, no dialog).
        // The old check blocked the redirect for up to 15s and — when an update was available — CANCELLED
        // the redirect to pop a Sparkle dialog that stranded the user (a standard child account can't
        // install it anyway). That was the "open just hangs" experience. Redirect now; keep it instant.
        DDLogInfo(@"Blinkered: bare launch (paired) — refreshing agent + redirecting immediately (daemon handles updates)");
        [self blinkeredRefreshAgentIfPaired];
        [self blinkeredDoBareLaunchRedirect];
        return;
    } else {
        [self applicationDidFinishLaunchingProceed];
    }
}

// Sparkle: no update available — redirect immediately.
- (void)updaterDidNotFindUpdate:(SPUUpdater *)updater {
    if (!_blinkeredPendingRedirect) return;
    DDLogInfo(@"Blinkered: no update found — redirecting");
    [NSObject cancelPreviousPerformRequestsWithTarget:self
                                             selector:@selector(blinkeredDoBareLaunchRedirect)
                                               object:nil];
    _blinkeredPendingRedirect = NO;
    [self blinkeredDoBareLaunchRedirect];
}

// Sparkle: update is available — cancel the redirect and let Sparkle show its dialog.
// If the user installs, Sparkle restarts the app. If they dismiss, the app stays
// open (no kiosk mode); they can quit manually or it will redirect on the next launch.
- (void)updater:(SPUUpdater *)updater didFindValidUpdate:(SUAppcastItem *)item {
    if (!_blinkeredPendingRedirect) return;
    DDLogInfo(@"Blinkered: update found (%@) — cancelling redirect, showing Sparkle dialog", item.versionString);
    [NSObject cancelPreviousPerformRequestsWithTarget:self
                                             selector:@selector(blinkeredDoBareLaunchRedirect)
                                               object:nil];
    _blinkeredPendingRedirect = NO;
    // Dismiss the splash/About window (shown at NSMainMenuWindowLevel+5) so the
    // Sparkle update dialog isn't stuck behind it, and bring the app forward so the
    // dialog is key and clickable.
    [self.aboutWindowController closeAboutWindow:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)blinkeredDoBareLaunchRedirect {
    _blinkeredPendingRedirect = NO;
    // An UNPAIRED device (no agent.json) goes to the pairing page — the parent enters their
    // dashboard pairing code, no sign-in needed. A paired device goes to the student landing.
    NSArray *appSupportDirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[appSupportDirs firstObject]
        stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    BOOL paired = [self blinkeredIsPaired];
    NSString *target;
    if (paired) {
        // Pass the device id + token to the dashboard so it can run shared-device kid mode. The
        // dashboard opens in the DEFAULT browser, which may not have the pairing stored locally,
        // so the token has to come from agent.json here.
        NSString *did = nil, *dtok = nil;
        NSData *data = [NSData dataWithContentsOfFile:agentJson];
        if (data) {
            NSDictionary *creds = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if ([creds isKindOfClass:[NSDictionary class]]) {
                if ([creds[@"id"] isKindOfClass:[NSString class]]) did = creds[@"id"];
                if ([creds[@"token"] isKindOfClass:[NSString class]]) dtok = creds[@"token"];
            }
        }
        NSCharacterSet *q = [NSCharacterSet URLQueryAllowedCharacterSet];
        if (did.length && dtok.length) {
            // Send paired devices to /student.html — the polished kid dashboard
            // (greeting, named user bar, switch user, focus tab). Pass the
            // device id+token so tryStartKidMode picks them up regardless of
            // what's in the browser's localStorage. /student.html handles
            // both assigned (one persona) and shared (PIN picker) devices
            // since v0.9.301.
            target = [NSString stringWithFormat:@"https://blinkered.com.au/student.html?did=%@&dtok=%@",
                      [did stringByAddingPercentEncodingWithAllowedCharacters:q],
                      [dtok stringByAddingPercentEncodingWithAllowedCharacters:q]];
        } else {
            target = @"https://blinkered.com.au/student.html";
        }
    } else if (blinkeredUpdaterDaemonInstalled()) {
        // Unpaired, but the root updater daemon is present — so this device was set up by the PARENT
        // installer (.pkg, or the SMAppService card). Nothing else installs that daemon, so this is
        // unambiguously a parent-managed device with a parent present holding a pairing code. Send it
        // STRAIGHT to the pairing screen — not the generic (focus-first) welcome chooser, where the
        // parent would have to hunt for the pairing option under a "Have a setup code?" toggle.
        //
        // Carry the mode into pairing when we can OBSERVE it. The .pkg is the Enforced artifact
        // (/downloads?for=parent) and its postinstall is the only thing that writes this plist — so its
        // presence IS the parent's Enforced choice, materialised on disk. Declaring an observation
        // beats trusting a stored flag, and unlike a localStorage hint it can't be lost between the
        // browser that downloaded and the one that pairs.
        //
        // Deliberately gated on the PKG plist specifically, not blinkeredUpdaterDaemonInstalled(): the
        // SMAppService variant also satisfies that check but is the legacy "Secure this device" card
        // path, which says nothing about Enforced. Ambiguous → say nothing and let it default
        // Cooperative (the safe default), rather than mis-tag a device as Enforced.
        BOOL pkgInstalled = [[NSFileManager defaultManager]
            fileExistsAtPath:@"/Library/LaunchDaemons/app.blinkered.updater.plist"];
        target = pkgInstalled ? @"https://blinkered.com.au/pair?mode=enforced"
                              : @"https://blinkered.com.au/pair";
    } else {
        // Unpaired and unmanaged: land on the welcome screen where the user chooses how they're using
        // Blinkered (parent pairing / joining a class / self-serve Focus Time).
        target = @"https://blinkered.com.au/welcome";
    }
    DDLogInfo(@"Blinkered: bare launch redirect — opening %@ (paired=%d)", target, paired);
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:target]];
    // We've just opened the correct destination (welcome, or the paired student page). Tell the
    // terminate handler NOT to also open student.html on quit — which would otherwise land on top
    // of the welcome page (and, if the default browser is signed in, show the dashboard instead
    // of the welcome/pairing screen we want). A file-static flag is used rather than
    // browserController.blinkeredWebReturn because browserController may not exist on this path.
    _blinkeredSkipTerminateReturn = YES;
    quittingMyself = YES;
    [NSApp terminate:self];
}

// ── Early screen covering on session launch ──────────────────────────────────
// Cover all screens with the black cap windows the moment we know this is a
// session launch — before the config is parsed and long before kiosk mode — so
// the first thing on screen is black + the splash, never the user's desktop.
// These are the SAME capWindows the rest of the lifecycle manages: coverScreens
// adopts them in place, changeWindowLevels re-levels them per the loaded config,
// and every exit path closes them via closeCapWindows.
//
// While this flag is set (cleared when startKioskModeThirdPartyAppsAllowed:
// applies the loaded settings), coverScreens keeps the covers at the elevated
// level even though org_safeexambrowser_elevateWindowLevels still reads NO.
static BOOL _blinkeredEarlyCoversActive = NO;

- (void)blinkeredEarlyCoverScreens
{
    // Not for: Preferences launch (option key), pairing (savepair saves + quits),
    // and never twice.
    if (_alternateKeyPressed || _blinkeredSavePair || self.capWindows.count > 0) {
        return;
    }
    DDLogInfo(@"Blinkered: covering screens early (session launch, settings not loaded yet)");
    _blinkeredEarlyCoversActive = YES;
    NSArray *coveringWindows = [self fillScreensWithCoveringWindows:coveringWindowBackground
                                                        windowLevel:NSMainMenuWindowLevel+2
                                                     excludeMenuBar:NO];
    if (!self.capWindows) {
        self.capWindows = [NSMutableArray arrayWithArray:coveringWindows];
    } else {
        [self.capWindows removeAllObjects];
        [self.capWindows addObjectsFromArray:coveringWindows];
    }
    // The splash (if already shown) was leveled for a non-elevated environment —
    // keep it above the covers.
    if (self.aboutWindow.isVisible) {
        [self.aboutWindow newSetLevel:NSMainMenuWindowLevel+5];
    }
}

// ── Bottom-edge reveal of the main window ─────────────────────────────────────
// Poll the cursor; when it reaches the very bottom of the main window's screen AND
// a separate browser window is currently covering the content, bring the main
// window forward so its tab bar is reachable. Gated on "covered" so it never
// reorders windows when nothing is in front.
static NSTimer *_mainWindowRevealTimer = nil;
static BOOL _mainWindowRevealArmed = YES;
static BOOL _mainWindowLevelRaised = NO;
static NSInteger _mainWindowOriginalLevel = 0;
// How many consecutive ~0.15s ticks the cursor has rested at the very bottom edge. We only
// reveal after a short dwell so quick passes (e.g. scrolling to the bottom of a full-window
// site) don't flicker the reveal up and down.
static int _bottomDwell = 0;
// YES while the main window is showing an embeddable site (e.g. Alto) raised above the
// 🪟 site windows — kept opaque + on top until a separate site window is activated.
static BOOL _mainWindowShowingEmbedded = NO;
// The site window that was in front when the tab bar was revealed, so dismissing the
// bar returns to exactly that window (not an arbitrary one from the unordered list).
static __weak NSWindow *_prevFrontSite = nil;

- (void)startMainWindowBottomEdgeReveal {
    if (_mainWindowRevealTimer) return;
    // The web bridge posts this when an embeddable site (e.g. Alto) is selected, so we can
    // raise the main window above the 🪟 site windows and show it opaque.
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(blinkeredFocusMainContent:)
                                                 name:@"BlinkeredFocusMainContent"
                                               object:nil];
    // The web bridge posts this when the parent picks "Set up automatic updates" from the locked-session
    // ⋯ menu (or the student-dashboard device-setup affordance) — re-open the updater setup card.
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(blinkeredShowAutoUpdateSetup)
                                                 name:@"BlinkeredShowAutoUpdateSetup"
                                               object:nil];
    // Same, for the Enforced assisted-manual setup card — so a parent who tapped "Not now" can come back
    // and finish, without re-pairing. Self-gated to Enforced.
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(blinkeredShowEnforcedSetup)
                                                 name:@"BlinkeredShowEnforcedSetup"
                                               object:nil];
    // §14.2 — the lock page's Master Exit Code box, validated HERE against this session's baked hash
    // so it works with no server. The bridge message is origin-gated in SEBBrowserController; every
    // authority decision (home-only, class refusal, empty-bake refusal, the compare itself) is in
    // blinkeredMasterCodeBridgeRequest:, alongside the Cmd+Q path it reuses verbatim.
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(blinkeredMasterCodeBridgeRequest:)
                                                 name:@"BlinkeredMasterCodeBridgeRequest"
                                               object:nil];
    // [P2R2-14] Page navigation clears the bounded double-Cmd+Q latch.
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(blinkeredPageChromeReady)
                                                 name:@"BlinkeredPageChromeReady"
                                               object:nil];
    // Tell the main page whenever a separate site window gains focus, so usage tracking
    // records time on full-window sites (Office, Alto) even when switched to directly.
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(blinkeredSiteWindowBecameKey:)
                                                 name:NSWindowDidBecomeKeyNotification
                                               object:nil];
    __weak typeof(self) weakSelf = self;
    _mainWindowRevealTimer = [NSTimer scheduledTimerWithTimeInterval:0.15
                                                             repeats:YES
                                                               block:^(NSTimer * _Nonnull timer) {
        [weakSelf checkMainWindowBottomEdge];
    }];
}

- (void)checkMainWindowBottomEdge {
    NSWindow *mainWin = self.browserController.mainBrowserWindow;
    if (!mainWin) return;

    // If we raised the main window above a covering window and the user has since
    // activated a separate browser window (e.g. clicked Office in the tab bar, making
    // it key), drop the main window back to its original level so that window shows on
    // top again. makeKeyAndOrderFront alone can't beat the covering window's higher
    // level, which is why raising/restoring the level is necessary.
    NSWindow *keyWinTop = [NSApplication sharedApplication].keyWindow;
    if (keyWinTop && keyWinTop != mainWin && [keyWinTop isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) {
        // A separate site window is now active — the main window is no longer the front
        // content. Clear embedded state and drop any raised level/overlay so that window
        // shows on top again (makeKeyAndOrderFront alone can't beat a higher level).
        _mainWindowShowingEmbedded = NO;
        if (_mainWindowLevelRaised) {
            _mainWindowLevelRaised = NO;
            [self setMainWindowOverlay:NO];
            [mainWin setLevel:_mainWindowOriginalLevel];
        }
    }

    // Blinkered: the bottom-edge reveal is gone — Join class + Exit now live in the
    // always-visible top bar (which shows in the strip site windows leave free), so there's
    // nothing to reveal at the bottom. We keep only the restore-on-key logic above.
    return;

    NSScreen *screen = mainWin.screen ?: [NSScreen mainScreen];
    if (!screen) return;
    NSRect f = screen.frame;
    NSPoint m = [NSEvent mouseLocation];
    // Bottom-edge reveal only: the top browser tabs are always visible in the strip the
    // site windows leave free, so they need no reveal — only the bottom action bar does.
    BOOL atBottom = (m.x >= NSMinX(f) && m.x <= NSMaxX(f) && m.y <= NSMinY(f) + 2.0);
    if (!atBottom) {
        _bottomDwell = 0;   // left the edge — reset the dwell
        if (m.y > NSMinY(f) + 40.0) {
            _mainWindowRevealArmed = YES; // re-arm once clear of the edge
            // If we raised the main (transparent) window for the tab bar but the user
            // moved away without activating another window, drop it back so the covered
            // site is front and interactive again — instead of staying dark/raised.
            // (Not while showing an embeddable site — that stays raised + opaque on top.)
            if (_mainWindowLevelRaised && !_mainWindowShowingEmbedded && [NSApplication sharedApplication].keyWindow == mainWin) {
                _mainWindowLevelRaised = NO;
                [self setMainWindowOverlay:NO];
                [mainWin setLevel:_mainWindowOriginalLevel];
                // Return to exactly the window that was in front before the reveal. Fall
                // back to the front-most site (orderedWindows) only if it has since closed.
                NSWindow *restoreSite = (_prevFrontSite && _prevFrontSite.isVisible) ? _prevFrontSite : nil;
                if (!restoreSite) {
                    for (NSWindow *w in [NSApplication sharedApplication].orderedWindows) {
                        if (w == mainWin || !w.isVisible) continue;
                        if ([w isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) { restoreSite = w; break; }
                    }
                }
                if (restoreSite) [restoreSite makeKeyAndOrderFront:nil];
                _prevFrontSite = nil;
            }
        }
        return;
    }
    if (!_mainWindowRevealArmed) return;
    // While an embeddable site is shown, the main window is already front + opaque, so the
    // web tab bar reveals itself — don't re-raise it transparent over the live site.
    if (_mainWindowShowingEmbedded) return;
    // Require a short dwell at the very bottom before revealing, so merely scrolling past
    // the bottom edge of a full-window site doesn't flicker the bar up and down.
    if (++_bottomDwell < 4) return;   // ~0.6s at 0.15s/tick

    // The front-most site window the user is viewing (orderedWindows is front-to-back),
    // so we can return to exactly it when the tab bar is dismissed. Using the unordered
    // -windows list here surfaced an arbitrary window (e.g. Canvas instead of Office).
    NSWindow *coveringWindow = nil;
    for (NSWindow *w in [NSApplication sharedApplication].orderedWindows) {
        if (w == mainWin || !w.isVisible) continue;
        if ([w isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) { coveringWindow = w; break; }
    }
    if (coveringWindow) {
        _mainWindowRevealArmed = NO;
        _prevFrontSite = coveringWindow;   // remember it for the drop-back below
        DDLogDebug(@"Blinkered: cursor at screen edge — raising main window above the covering window to reach the tabs");
        if (!_mainWindowLevelRaised) {
            _mainWindowOriginalLevel = mainWin.level;
            _mainWindowLevelRaised = YES;
        }
        // Raise the main window just above the covering window so its tab bar is on top
        // and clickable. Restored when the user activates a separate window again (above).
        [mainWin setLevel:coveringWindow.level + 1];
        [mainWin makeKeyAndOrderFront:nil];
        // Make the raised main window see-through so the covered site stays visible
        // behind just the tab-bar bubble (rather than a dark "open elsewhere" screen).
        [self setMainWindowOverlay:YES];
    }
}

// Toggle the main window into a transparent "overlay" so the site in the covering
// window shows through behind the tab bar. Window + WKWebView + page background all
// go clear; restored to opaque when the overlay ends. Guarded so a failure degrades
// to the old opaque behaviour rather than crashing.
static BOOL _overlaySaved = NO;
static BOOL _overlayOrigOpaque = YES;
static NSColor *_overlayOrigBg = nil;
- (void)setMainWindowOverlay:(BOOL)on {
    NSWindow *mainWin = self.browserController.mainBrowserWindow;
    if (!mainWin) return;
    if (on) {
        if (!_overlaySaved) {
            _overlayOrigOpaque = mainWin.opaque;
            _overlayOrigBg = mainWin.backgroundColor;
            _overlaySaved = YES;
        }
        mainWin.opaque = NO;
        mainWin.backgroundColor = [NSColor clearColor];
    } else {
        if (_overlaySaved) {
            mainWin.opaque = _overlayOrigOpaque;
            mainWin.backgroundColor = _overlayOrigBg ?: [NSColor whiteColor];
            _overlaySaved = NO;
        }
    }
    id abstract = [mainWin valueForKey:@"webView"];
    if (abstract && [abstract respondsToSelector:@selector(nativeWebView)]) {
        id wk = [abstract performSelector:@selector(nativeWebView)];
        if ([wk isKindOfClass:NSClassFromString(@"WKWebView")]) {
            @try { [wk setValue:@(!on) forKey:@"drawsBackground"]; } @catch (__unused NSException *e) {}
            NSString *js = [NSString stringWithFormat:@"window.__blinkeredOverlay && window.__blinkeredOverlay(%@)", on ? @"true" : @"false"];
            @try { [wk performSelector:@selector(evaluateJavaScript:completionHandler:) withObject:js withObject:nil]; } @catch (__unused NSException *e) {}
        }
    }
}

// A separate 🪟 site window gained focus (the user switched to it directly, not via the
// tab bar). Tell the main page which site, so it can record the active site for usage —
// otherwise time on full-window sites switched-to directly would be missed.
- (void)blinkeredSiteWindowBecameKey:(NSNotification *)note {
    NSWindow *win = note.object;
    NSWindow *mainWin = self.browserController.mainBrowserWindow;
    if (!win || win == mainWin) return;
    if (![win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) return;
    NSString *url = [win valueForKey:@"blinkeredOriginalURLString"] ?: @"";
    if (url.length == 0) {
        id abstract = [win valueForKey:@"webView"];
        if (abstract && [abstract respondsToSelector:@selector(nativeWebView)]) {
            id wk = [abstract performSelector:@selector(nativeWebView)];
            if ([wk isKindOfClass:NSClassFromString(@"WKWebView")]) {
                NSURL *u = [wk valueForKey:@"URL"];
                url = u.absoluteString ?: @"";
            }
        }
    }
    if (url.length == 0 || !mainWin) return;
    id mainAbstract = [mainWin valueForKey:@"webView"];
    if (mainAbstract && [mainAbstract respondsToSelector:@selector(nativeWebView)]) {
        id mwk = [mainAbstract performSelector:@selector(nativeWebView)];
        if ([mwk isKindOfClass:NSClassFromString(@"WKWebView")]) {
            // `url` is a SITE window's current URL — page-navigable, so page-chosen — and this
            // evaluates in the SHELL's main frame, which is the same reach that made §0 severe.
            // Escaping was correct here; routed through the one helper so it stays that way.
            NSString *js = [NSString stringWithFormat:@"window.__blinkeredWindowFocused && window.__blinkeredWindowFocused(%@)",
                            [SEBAbstractWebView blinkeredJSStringLiteral:url]];
            @try { [mwk performSelector:@selector(evaluateJavaScript:completionHandler:) withObject:js withObject:nil]; } @catch (__unused NSException *e) {}
        }
    }
}

// An embeddable site (loaded in the main window's iframe) was selected from the tab
// bar. Raise the main window above the open 🪟 site windows and show it opaque, so the
// embedded site appears on top of them rather than behind. Restored when the user
// activates a separate site window again (handled in checkMainWindowBottomEdge).
- (void)blinkeredFocusMainContent:(NSNotification *)note {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSWindow *mainWin = self.browserController.mainBrowserWindow;
        if (!mainWin) return;
        NSInteger topLevel = mainWin.level;
        BOOL anySite = NO;
        for (NSWindow *w in [NSApplication sharedApplication].windows) {
            if (w == mainWin || !w.isVisible) continue;
            if (![w isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) continue;
            anySite = YES;
            if (w.level > topLevel) topLevel = w.level;
        }
        [self setMainWindowOverlay:NO];      // opaque — show the embedded site, not see-through
        if (anySite) {
            if (!_mainWindowLevelRaised) { _mainWindowOriginalLevel = mainWin.level; _mainWindowLevelRaised = YES; }
            [mainWin setLevel:topLevel + 1];
        }
        _mainWindowShowingEmbedded = YES;
        // Activate the app so the main window truly becomes key. A WKWebView does not paint
        // content loaded while its window/app is inactive — when the teacher pushes a site
        // remotely there's no student click to wake it, so it stays black until tapped.
        // Activating + keying forces the render.
        [[NSApplication sharedApplication] activateIgnoringOtherApps:YES];
        [mainWin makeKeyAndOrderFront:nil];
        // Belt-and-suspenders: nudge the web view's frame by 1px and back to force a repaint
        // for the remote-push case where activation alone doesn't trigger a composite.
        id mainAbstract = [mainWin valueForKey:@"webView"];
        if (mainAbstract && [mainAbstract respondsToSelector:@selector(nativeWebView)]) {
            NSView *wv = [mainAbstract performSelector:@selector(nativeWebView)];
            if ([wv isKindOfClass:[NSView class]]) {
                NSRect fr = wv.frame;
                wv.frame = NSInsetRect(fr, 0, 1);
                wv.frame = fr;
                [wv setNeedsDisplay:YES];
            }
        }
    });
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// P1 Bug-A paint recovery — see docs/MAC_LOCK_PAINT_SCREENTIME_P1_PLAN.md (v3, Phase 1+2).
//
// The lock screen sometimes renders fully BLACK (WKWebView not presenting while inactive on wake, or a
// stuck cap window). Own-window CGWindowListCreateImage is the GROUND-TRUTH detector: it images the
// render server's composited surfaces (downstream of every failure mode) and — capturing our OWN
// windows — needs NO Screen Recording (TCC) permission. On a lock trigger (reveal / wake / occlusion /
// periodic) we settle, capture, and if the browser window is black (near-black pixel fraction + missing
// tab-band, confirmed across two captures) run a capture-VERIFIED ladder nudge → reinforce → reload,
// then post evidence-bearing telemetry (kind:'paint_fault'). If capture ever fails we BAIL — never run
// the ladder, never prompt for Screen Recording (degrade, don't prompt).
//
// SHADOW MODE (reviewer ruling): the FIRST deploy DETECTS + reports telemetry but does NOT act —
// no nudge / reinforce / reload — so the uncalibrated thresholds below can never disrupt a healthy
// lock. A follow-up release flips this YES once shadow telemetry (incl. the dual-band light fractions)
// has calibrated the constants + settled the tab-band orientation on real macOS 15/26 hardware.
//
// DO NOT FLIP THIS ON THE STRENGTH OF THE SHADOW TELEMETRY — the telemetry that accumulated under it
// is not evidence of anything. Every one of the ~799 shadow reports was a FALSE POSITIVE: the window
// this module captures is NSWindowSharingNone, so CGWindowListCreateImage returned an empty frame and
// blinkeredFrameIsBlack was true unconditionally (see the gate in blinkeredCheckPaintForTrigger, which
// now bails before the capture). The constants below were never calibrated by it, and the "settle the
// tab-band orientation from real data" plan never had real data. Flipping this before the capture is
// replaced with a probe that can actually observe the page would have run nudge → activate →
// reinforceKioskMode → reload on EVERY locked device every 45 seconds, permanently.
static const BOOL         kBPRRecoveryEnabled  = NO;
// TUNABLES: first estimates, calibrated during Phase-1 "measure".
// Three near-black cutoffs: the decision uses 16; 8 and 32 are ALSO reported so the recovery-enable
// flip can see whether a tighter (8) cutoff would miss real blacks or a looser (32) one would false-fire
// on dark content — you can't re-derive those from a single boolean-per-pixel fraction.
static const CGFloat      kBPRBlackCut8        = 8.0/255.0;
static const CGFloat      kBPRBlackCut16       = 16.0/255.0; // primary near-black cutoff
static const CGFloat      kBPRBlackCut32       = 32.0/255.0;
static const CGFloat      kBPRBlackFractionMin = 0.995;      // ≥ this near-black fraction ⇒ black frame
static const CGFloat      kBPRBlackNoTabFrac   = 0.90;       // ≥ this AND no top tab-band light ⇒ also black
static const CGFloat      kBPRTabBandPoints    = 46.0;       // TOP band that should hold the light tab bar
static const CGFloat      kBPRTabBandLightFrac = 0.02;       // ≥ this light fraction in the band ⇒ tab bar present
static const NSTimeInterval kBPRSettle         = 1.2;        // let wake/reveal settle before the first capture
static const NSTimeInterval kBPRVerifyGap      = 0.35;       // between the persistence / post-rung captures
// TODO(recovery-flip): kBPRReloadVerify is too short for a real page reload — a successful reload is often
// still loading (black window bg) at verify time, which would burn the reload budget / set gaveUp on a
// working recovery. Before enabling recovery, key this off the reload's didFinishLoad (+settle) or ~8s.
static const NSTimeInterval kBPRReloadVerify   = 1.5;        // reload is async — wait longer to verify it
static const NSInteger      kBPRMaxReloads     = 3;          // rung-3 reloads per session (rate limit)
static const NSTimeInterval kBPRPeriodic       = 45.0;       // periodic capture while locked (in-use black)
static const NSTimeInterval kBPRMinInterval    = 4.0;        // debounce: don't run the whole check faster than this

// A single capture's analysis: near-black fractions at three cutoffs + top/bottom band light fractions.
typedef struct { BOOL ok; CGFloat black8, black16, black32, topBand, bottomBand; } BPRFrame;

// ── Wake-edge recovery (MAC_WAKE_EDGE_RECOVERY_PLAN.md v2 §1; targeted re-review GO, 68148ab7) ──
// BWE = Blinkered Wake Edge. A dedicated action path off blinkeredScreensDidWake: — NOT part of the
// (shadow) capture detector above. Nudge always; reload only on snapshot-timeout AND
// rAF-not-advanced-since-wake. No CGWindowList capture anywhere in this path, so the LPM skip above
// does NOT apply here (review F1/F10 — LPM was not even the incident condition).
static const NSTimeInterval kBWENudgeMinInterval  = 60.0;   // wake-storm guard: ≤1 nudge per 60s
static const NSTimeInterval kBWESettle            = 1.2;    // let the wake settle before probing
static const NSTimeInterval kBWEProbeDeadline     = 5.0;    // snapshot + rAF-read deadline (~5s, one snapshot retry — review Q1/F6)
static const NSTimeInterval kBWERevealGrace       = 30.0;   // bail within 30s of launch/reveal (hold safety timeout is 15s — F8)
static const NSInteger      kBWEMaxReloadsSession = 6;      // outer cap; ≤1 reload per wake-edge (F6)
static NSTimeInterval _bweLastNudgeAt   = 0;
static NSTimeInterval _bweRevealAt      = 0;
static NSInteger      _bweSessionReloads = 0;
static NSInteger      _bweWakeOrdinal    = 0;
// Defined (initialized) with the offline-exit statics later in this file; tentative definition here so
// the wake path's reload arm can consult it (F5: never reload while the offline panel is showing).
static BOOL _blinkeredOfflinePanelShowing;

- (BOOL)blinkeredPaintLockActive {
    SEBBrowserWindow *win = self.browserController.mainBrowserWindow;
    if (!(self.sessionRunning && !_isAACEnabled && win)) return NO;
    // CRITICAL: never run while the window is DELIBERATELY held black until first paint
    // (SEBBrowserWindow blinkeredHoldContentUntilFirstPaint / blinkeredContentHeld) — that black is
    // designed (launch/reload), not the bug. Reading black during the hold would false-fire on EVERY
    // lock launch. Typed property call (refactor-proof; a silent KVC breakage would re-introduce the
    // launch false-fire once recovery is enabled — the worst failure, so no KVC here).
    // TODO(recovery-flip): consider a belt-and-braces "ignore the held-gate after ~30s of session" so a
    // stuck held==YES (no independent timeout beyond the reveal safety timer) can't suppress detection.
    return !win.blinkeredContentHeld;
}

- (void)blinkeredArmPaintRecovery {
    if (_isAACEnabled) return;
    _blinkeredReloadCount = 0;              // reset per session, even if the controller is already armed
    _bweSessionReloads = 0;                 // wake-edge budgets are per SESSION (review F6) — reset with it
    _bweWakeOrdinal = 0;
    _bweLastNudgeAt = 0;
    _bweRevealAt = 0;
    _blinkeredPaintGaveUp = NO;
    // CONDITION 5, second half. Fix 2's ramp, its navigation counter and the SHARED in-flight
    // deadline are per-session state exactly as the four lines above are, so they reset HERE and
    // nowhere else. A second reset point is how two budgets drift apart.
    [self blinkeredHomeRetryResetForSession];
    if (_blinkeredPaintArmed) return;
    _blinkeredPaintArmed = YES;
    [[[NSWorkspace sharedWorkspace] notificationCenter] addObserver:self selector:@selector(blinkeredScreensDidWake:)
                                                              name:NSWorkspaceScreensDidWakeNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(blinkeredWindowOcclusionChanged:)
                                                 name:NSWindowDidChangeOcclusionStateNotification object:nil];
    // Reveal check fires when content is ACTUALLY shown (SEBBrowserWindow posts this from
    // blinkeredRevealContent), NOT at performAfterStartActions — which lands on the designed hold-black.
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(blinkeredContentRevealed:)
                                                 name:@"BlinkeredContentRevealed" object:nil];
    _blinkeredPaintTimer = [NSTimer scheduledTimerWithTimeInterval:kBPRPeriodic target:self
                                selector:@selector(blinkeredPeriodicPaintCheck:) userInfo:nil repeats:YES];
    DDLogInfo(@"Blinkered paint recovery armed (recovery %@)", kBPRRecoveryEnabled ? @"ENABLED" : @"SHADOW");
}

- (void)blinkeredDisarmPaintRecovery {
    // F8. BEFORE the early return, and unconditional. _blinkeredPaintArmed is NO for the whole
    // period the offline panel is up (the arm below rides the same starved launch timer as F1) —
    // which is exactly the period Fix 2 is armed in. Behind the early return this was a comment,
    // not a mechanism.
    [self blinkeredHomeRetryCancelForTeardown];
    if (!_blinkeredPaintArmed) return;
    _blinkeredPaintArmed = NO;
    [[[NSWorkspace sharedWorkspace] notificationCenter] removeObserver:self name:NSWorkspaceScreensDidWakeNotification object:nil];
    [[NSNotificationCenter defaultCenter] removeObserver:self name:NSWindowDidChangeOcclusionStateNotification object:nil];
    [[NSNotificationCenter defaultCenter] removeObserver:self name:@"BlinkeredContentRevealed" object:nil];
    [_blinkeredPaintTimer invalidate];
    _blinkeredPaintTimer = nil;
}

- (void)blinkeredScreensDidWake:(NSNotification *)n {
    _blinkeredLastWakeAt = [NSDate timeIntervalSinceReferenceDate];
    [self blinkeredCheckPaintForTrigger:@"wake"];
    // Wake-edge recovery (plan v2 §1.1): its OWN path, deliberately NOT inside
    // blinkeredCheckPaintForTrigger: — that pipeline is dead under LPM / give-up / debounce and
    // runs the void capture (review F1). This path does no capture and ignores LPM.
    [self blinkeredWakeEdgeRecovery];
}

- (void)blinkeredWindowOcclusionChanged:(NSNotification *)n {
    NSWindow *w = n.object;
    if (w == self.browserController.mainBrowserWindow && (w.occlusionState & NSWindowOcclusionStateVisible)) {
        [self blinkeredCheckPaintForTrigger:@"occlusion"];
    }
}

- (void)blinkeredContentRevealed:(NSNotification *)n {
    _bweRevealAt = [NSDate timeIntervalSinceReferenceDate];   // wake-edge launch/reveal grace anchor (review F8)
    [self blinkeredCheckPaintForTrigger:@"reveal"];
}

- (void)blinkeredPeriodicPaintCheck:(NSTimer *)t {
    // C4 (§5): a non-suppressing liveness re-check for the empty-content backdrop. It only ever
    // REMOVES, and only when the main frame actually holds a document, so it cannot repaint white
    // and it touches no flag the paint or wake-edge paths read.
    [self.browserController.mainBrowserWindow blinkeredRecheckEmptyContentBackdrop];
    [self blinkeredCheckPaintForTrigger:@"periodic"];
}

// Debounced entry point: gate to a live lock (content revealed), settle, run the detector on the main queue.
- (void)blinkeredCheckPaintForTrigger:(NSString *)trigger {
    if (_blinkeredPaintGaveUp) return;                       // unrecoverable this session — stop re-running
    if (![self blinkeredPaintLockActive]) return;
    // Low Power Mode throttles the GPU. A synchronous window capture (CGWindowListCreateImage + a
    // downsample draw) then becomes slow, and doing it on the MAIN THREAD (as this used to) stalled the
    // very thread WebKit needs to composite the page — starving the repaint and turning a brief LPM
    // slowness into a PERSISTENT black + app hang (observed 3.6.172, Leggie's Mac). This module is
    // shadow/detect-only, so skip it entirely under Low Power Mode: nothing is lost and the hang vector
    // is removed. Belt-and-braces, the capture below also now runs off the main thread.
    if (@available(macOS 12.0, *)) {
        if (NSProcessInfo.processInfo.isLowPowerModeEnabled) return;
    }
    NSTimeInterval nowT = [NSDate timeIntervalSinceReferenceDate];
    if (nowT - _blinkeredLastPaintCheck < kBPRMinInterval) return;
    _blinkeredLastPaintCheck = nowT;
    if (!_blinkeredPaintQueue) {
        _blinkeredPaintQueue = dispatch_queue_create("app.blinkered.paint-capture", DISPATCH_QUEUE_SERIAL);
    }
    NSTimeInterval settle = ([trigger isEqualToString:@"reveal"] || [trigger isEqualToString:@"wake"]) ? kBPRSettle : 0.2;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(settle * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (![self blinkeredPaintLockActive]) return;
        NSWindow *win = self.browserController.mainBrowserWindow;
        if (!win || win.windowNumber <= 0) return;           // deferred/off-screen → nothing to capture
        // THE DETECTOR CANNOT SEE THIS WINDOW, and for three weeks it did not know that. The main
        // browser window is created with sharingType = NSWindowSharingNone (SEBOSXBrowserController,
        // "don't allow other processes to read window contents") — the anti-screenshot control. The
        // WindowServer enforces that as a property of the WINDOW, not as a check on the caller, so
        // CGWindowListCreateImage returns a uniformly empty frame even to the owning process. This
        // module's "capture our OWN window (permission-free)" premise was simply wrong.
        //
        // The result was 799 paint_fault reports across 6 devices and every version from 3.6.171 —
        // black16 = 1.000 and topBandLightFraction = EXACTLY 0.0000 on all of them, all four triggers,
        // flat across all 24 hours — while nobody ever saw a black lock. It was measuring the privacy
        // setting, not the page. Bailing here rather than downstream also makes the recovery-flip safe
        // by construction: kBPRRecoveryEnabled can never drive a ladder off a blind capture, which
        // would have fired nudge → activate → reload on EVERY locked device every 45 seconds.
        //
        // Any real fix replaces the capture with something that can actually observe the page — the
        // WebKit snapshot + rAF-advancement probe the wake-edge path already uses (and whose telemetry
        // varies properly, unlike this one's constant) — NOT by relaxing sharingType, which exists to
        // stop a locked session being screenshotted.
        if (win.sharingType == NSWindowSharingNone) {
            static dispatch_once_t onceBlind;
            dispatch_once(&onceBlind, ^{
                DDLogInfo(@"Blinkered paint: detector disabled — mainBrowserWindow is NSWindowSharingNone, so a capture reads black regardless of what the page painted");
            });
            return;
        }
        CGWindowID wid = (CGWindowID)win.windowNumber;        // read NSWindow state on the MAIN thread
        CGFloat winH = win.frame.size.height;
        // The heavy GPU capture + downsample runs OFF the main thread so a throttled/slow capture can
        // never stall the UI (the thread WebKit composites on). Only the ladder (UI work) hops back.
        dispatch_async(self.blinkeredPaintQueue, ^{
            BPRFrame f1 = [self blinkeredAnalyzeWindowID:wid winHeight:winH];
            if (!f1.ok) return;                              // capture failed → bail
            if (![self blinkeredFrameIsBlack:f1]) return;    // healthy
            // Persistence: require a second black capture (after a short gap) before touching anything.
            usleep((useconds_t)(kBPRVerifyGap * 1000000.0)); // background serial queue — safe to sleep
            BPRFrame f2 = [self blinkeredAnalyzeWindowID:wid winHeight:winH];
            if (!f2.ok || ![self blinkeredFrameIsBlack:f2]) return;   // transient, not persistent
            dispatch_async(dispatch_get_main_queue(), ^{
                if (![self blinkeredPaintLockActive]) return;
                [self blinkeredRunLadder:trigger frame:f2 startedAt:nowT];
            });
        });
    });
}

// A frame is black if almost all pixels are near-black (at the primary cutoff), OR (≥ the softer fraction
// AND the TOP tab-band isn't lit — i.e. the page chrome didn't paint). Orientation is the top band;
// telemetry reports both bands + three cutoffs so the choices are settled empirically before recovery ships.
- (BOOL)blinkeredFrameIsBlack:(BPRFrame)f {
    return (f.black16 >= kBPRBlackFractionMin) ||
           (f.topBand < kBPRTabBandLightFrac && f.black16 >= kBPRBlackNoTabFrac);
}

// Capture our OWN window (permission-free) → downsample → near-black pixel fractions at three cutoffs +
// TOP/BOTTOM band light fractions. .ok = NO if capture/analysis failed (caller bails — never runs the
// ladder, never prompts for TCC).
- (BPRFrame)blinkeredAnalyzeWindow:(NSWindow *)win {
    if (!win || win.windowNumber <= 0) { BPRFrame z = {0}; return z; }   // deferred/off-screen = 0 or −1
    return [self blinkeredAnalyzeWindowID:(CGWindowID)win.windowNumber winHeight:win.frame.size.height];
}

// Pure Core Graphics capture + analysis. Takes a CGWindowID + the window height (both read on the MAIN
// thread by the caller) and touches NO AppKit/NSWindow state, so it is safe to run on a background queue.
- (BPRFrame)blinkeredAnalyzeWindowID:(CGWindowID)wid winHeight:(CGFloat)winArg {
    BPRFrame f = {0};
    if (wid == 0) return f;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"   // CGWindowListCreateImage: deprecated (macOS 14), still functional; own-window capture stays TCC-free — see plan §1.2 fallback policy
    CGImageRef img = CGWindowListCreateImage(CGRectNull, kCGWindowListOptionIncludingWindow, wid,
                                             kCGWindowImageBoundsIgnoreFraming | kCGWindowImageNominalResolution);
#pragma clang diagnostic pop
    if (!img) return f;
    size_t srcW = CGImageGetWidth(img), srcH = CGImageGetHeight(img);
    if (srcW == 0 || srcH == 0) { CGImageRelease(img); return f; }
    const size_t W = 128, H = 128;
    uint8_t *buf = calloc(W * H * 4, 1);
    if (!buf) { CGImageRelease(img); return f; }
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(buf, W, H, 8, W * 4, cs, kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(cs);
    if (!ctx) { free(buf); CGImageRelease(img); return f; }
    CGContextSetInterpolationQuality(ctx, kCGInterpolationNone);
    CGContextDrawImage(ctx, CGRectMake(0, 0, W, H), img);
    CGImageRelease(img);
    const uint8_t cut8 = (uint8_t)(kBPRBlackCut8 * 255.0), cut16 = (uint8_t)(kBPRBlackCut16 * 255.0), cut32 = (uint8_t)(kBPRBlackCut32 * 255.0);
    CGFloat winH = winArg; if (winH < 1) winH = (CGFloat)srcH;
    NSUInteger bandRows = (NSUInteger)MAX(1.0, (kBPRTabBandPoints / winH) * (CGFloat)H);
    // CGBitmapContext memory row 0 = the VISUAL TOP of the window (the tab bar lives here). Report both
    // top and bottom band light fractions so the orientation assumption is verifiable from telemetry.
    NSUInteger nb8 = 0, nb16 = 0, nb32 = 0, total = W * H, topLight = 0, topTot = 0, botLight = 0, botTot = 0;
    for (size_t y = 0; y < H; y++) {
        BOOL isTop = (y < bandRows), isBot = (y >= H - bandRows);
        for (size_t x = 0; x < W; x++) {
            uint8_t *p = buf + (y * W + x) * 4;
            uint8_t mx = MAX(p[0], MAX(p[1], p[2]));         // max channel = the "least black" one
            if (mx <= cut8)  nb8++;
            if (mx <= cut16) nb16++;
            if (mx <= cut32) nb32++;
            BOOL lightForBand = (mx > cut16);                // band uses the primary cutoff
            if (isTop) { topTot++; if (lightForBand) topLight++; }
            if (isBot) { botTot++; if (lightForBand) botLight++; }
        }
    }
    CGContextRelease(ctx);
    free(buf);
    f.ok = YES;
    f.black8  = (CGFloat)nb8  / (CGFloat)total;
    f.black16 = (CGFloat)nb16 / (CGFloat)total;
    f.black32 = (CGFloat)nb32 / (CGFloat)total;
    f.topBand    = topTot ? (CGFloat)topLight / (CGFloat)topTot : 0;
    f.bottomBand = botTot ? (CGFloat)botLight / (CGFloat)botTot : 0;
    return f;
}

- (void)blinkeredNudgeWindow:(NSWindow *)win {
    [[NSApplication sharedApplication] activateIgnoringOtherApps:YES];
    [win makeKeyAndOrderFront:nil];
    id mainAbstract = [win valueForKey:@"webView"];
    if (mainAbstract && [mainAbstract respondsToSelector:@selector(nativeWebView)]) {
        NSView *wv = [mainAbstract performSelector:@selector(nativeWebView)];
        if ([wv isKindOfClass:[NSView class]]) {
            NSRect fr = wv.frame; wv.frame = NSInsetRect(fr, 0, 1); wv.frame = fr; [wv setNeedsDisplay:YES];
        }
    }
}

- (void)blinkeredReloadWindow:(NSWindow *)win {
    id mainAbstract = [win valueForKey:@"webView"];
    if (mainAbstract && [mainAbstract respondsToSelector:@selector(reload)]) {
        [mainAbstract performSelector:@selector(reload)];
    }
}

// Re-capture after `delay`; call back with whether the window is (still) black. A failed capture is
// treated as "not black" (recovered) so we never loop on a capture failure.
- (void)blinkeredVerifyAfter:(NSTimeInterval)delay window:(NSWindow *)win then:(void (^)(BOOL black))cb {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (!win || win.windowNumber <= 0 || !self.blinkeredPaintQueue) { cb(NO); return; }   // treat as not-black
        CGWindowID wid = (CGWindowID)win.windowNumber; CGFloat winH = win.frame.size.height;   // NSWindow read on main
        dispatch_async(self.blinkeredPaintQueue, ^{        // capture off-main, same as the detection path
            BPRFrame f = [self blinkeredAnalyzeWindowID:wid winHeight:winH];
            BOOL black = f.ok ? [self blinkeredFrameIsBlack:f] : NO;   // failed capture → "not black" so we never loop
            dispatch_async(dispatch_get_main_queue(), ^{ cb(black); });
        });
    });
}

// SHADOW mode: report the detection, do NOT act. RECOVERY mode: nudge → verify → reinforce → verify →
// reload → verify; report once. After the reload cap is hit and it's still black, mark gave-up so we
// stop re-running the ladder on every trigger (report once, then quiet until the session restarts).
// TODO(calibrate): multi-display — v1 recovers the main browser window; screenCount is in telemetry so
// we learn whether per-screen site windows also go black and need their own sweep.
- (void)blinkeredRunLadder:(NSString *)trigger frame:(BPRFrame)f startedAt:(NSTimeInterval)startedAt {
    NSWindow *win = self.browserController.mainBrowserWindow;
    if (!win) return;
    DDLogInfo(@"Blinkered paint: black lock CONFIRMED (trigger=%@ black16=%.3f top=%.3f bot=%.3f recovery=%@)",
              trigger, f.black16, f.topBand, f.bottomBand, kBPRRecoveryEnabled ? @"ON" : @"SHADOW");
    if (!kBPRRecoveryEnabled) {
        [self blinkeredReportPaint:trigger frame:f rung:0 recovered:NO shadow:YES startedAt:startedAt];
        return;
    }
    [self blinkeredNudgeWindow:win];
    [self blinkeredVerifyAfter:kBPRVerifyGap window:win then:^(BOOL black1) {
        if (!black1) { [self blinkeredReportPaint:trigger frame:f rung:1 recovered:YES shadow:NO startedAt:startedAt]; return; }
        [self reinforceKioskMode];
        [self blinkeredVerifyAfter:kBPRVerifyGap window:win then:^(BOOL black2) {
            if (!black2) { [self blinkeredReportPaint:trigger frame:f rung:2 recovered:YES shadow:NO startedAt:startedAt]; return; }
            if (self.blinkeredReloadCount >= kBPRMaxReloads) {
                _blinkeredPaintGaveUp = YES;   // stop re-running the ladder each trigger — report once
                [self blinkeredReportPaint:trigger frame:f rung:0 recovered:NO shadow:NO startedAt:startedAt];
                return;
            }
            self.blinkeredReloadCount++;
            [self blinkeredReloadWindow:win];
            [self blinkeredVerifyAfter:kBPRReloadVerify window:win then:^(BOOL black3) {
                if (black3 && self.blinkeredReloadCount >= kBPRMaxReloads) _blinkeredPaintGaveUp = YES;
                [self blinkeredReportPaint:trigger frame:f rung:(black3 ? 0 : 3) recovered:!black3 shadow:NO startedAt:startedAt];
            }];
        }];
    }];
}

// Post the evidence-bearing paint_fault telemetry (device-token authed, creds from agent.json — same
// idiom as blinkeredReportAgentRepaired). kind:'paint_fault' is spike-exempt server-side. Carries the
// three-cutoff black fractions + both band light fractions (to settle cutoff + orientation) and a
// shadow flag (detect-only vs acted).
- (void)blinkeredReportPaint:(NSString *)trigger frame:(BPRFrame)f
                        rung:(NSInteger)rung recovered:(BOOL)recovered shadow:(BOOL)shadow startedAt:(NSTimeInterval)startedAt {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[dirs firstObject] stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    NSData *cd = [NSData dataWithContentsOfFile:agentJson];
    NSDictionary *creds = cd ? [NSJSONSerialization JSONObjectWithData:cd options:0 error:nil] : nil;
    if (![creds isKindOfClass:[NSDictionary class]]) return;
    NSString *devId = creds[@"id"], *devTok = creds[@"token"];
    NSString *server = [creds[@"server"] isKindOfClass:[NSString class]] ? creds[@"server"] : @"https://blinkered.com.au";
    if (![devId isKindOfClass:[NSString class]] || ![devTok isKindOfClass:[NSString class]]) return;
    NSTimeInterval nowT = [NSDate timeIntervalSinceReferenceDate];
    // The TRUE panel state, not a proxy. This used to be `(nowT - _blinkeredLastWakeAt) < 5.0` — i.e.
    // "a wake notification fired in the last 5 seconds" — under a field named displaySlept. A locked Mac
    // sitting overnight with its screen off therefore reported displaySlept:false, which is precisely
    // what made a fleet of screen-off captures read as "screen on, window black". Report both: the panel
    // state, and (as wokeRecently) the thing the old expression actually measured.
    BOOL displaySlept = CGDisplayIsAsleep(CGMainDisplayID()) != 0;
    BOOL wokeRecently = (nowT - _blinkeredLastWakeAt) < 5.0;
    BOOL tabPresent = (f.topBand >= kBPRTabBandLightFrac);
    NSString *hyp = tabPresent ? @"unknown" : @"paint";   // black frame with no top tab-band ⇒ page chrome didn't paint
    NSString *appVer = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    CGFloat bf = f.black16;
    NSDictionary *body = @{ @"token": devTok, @"kind": @"paint_fault",
        @"exceptionType": @"PaintFault", @"method": (trigger ?: @"unknown"),
        @"appVersion": appVer, @"os": ([[NSProcessInfo processInfo] operatingSystemVersionString] ?: @""),
        @"trigger": (trigger ?: @"unknown"), @"hypothesis": hyp,
        @"blackPixelFraction": @(f.black16), @"blackFraction8": @(f.black8), @"blackFraction32": @(f.black32),
        @"tabBandPresent": @(tabPresent),
        @"topBandLightFraction": @(f.topBand), @"bottomBandLightFraction": @(f.bottomBand), @"shadow": @(shadow),
        @"rungRecovered": @(rung), @"recovered": @(recovered), @"displaySlept": @(displaySlept), @"wokeRecently": @(wokeRecently),
        @"msSinceTrigger": @((NSInteger)((nowT - startedAt) * 1000.0)), @"screenCount": @((NSInteger)[NSScreen screens].count) };
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/home/devices/%@/crash-report", server, devId]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    [[[NSURLSession sharedSession] dataTaskWithRequest:req] resume];
    DDLogInfo(@"Blinkered paint_fault%@: trigger=%@ black=%.3f top=%.3f rung=%ld recovered=%d", shadow ? @"(shadow)" : @"", trigger, bf, f.topBand, (long)rung, recovered);
}

// ── Wake-edge recovery implementation (plan v2 §1) ────────────────────────────

// Gates (§1.2, in order), then rung 1: the jitter-only sweep. Runs on the main queue (wake
// notifications arrive there). NEVER routes through blinkeredCheckPaintForTrigger:.
- (void)blinkeredWakeEdgeRecovery {
    // 1+2. Home lock active + hold/session gates. blinkeredPaintLockActive = sessionRunning,
    // not AAC, main window exists, not deliberately held black. The home-lock predicate is the
    // OR'd composition (re-review binding note): the launch-time startURL check first —
    // home_session.json alone reads false-negative until the lock page has loaded through the
    // /seb-sethomesession redirect, e.g. a device that slept right after lock launch.
    if (![self blinkeredPaintLockActive]) return;
    BOOL homeLock = [SEBBrowserWindow blinkeredIsHomeLockSession] || [self blinkeredHomeSessionInfo] != nil;
    if (!homeLock) return;
    // 3. Launch/reveal grace (F8): a wake racing a fresh launch must not double-paint.
    NSTimeInterval nowT = [NSDate timeIntervalSinceReferenceDate];
    if (_bweRevealAt > 0 && (nowT - _bweRevealAt) < kBWERevealGrace) return;
    // 4. Not quitting (unlock-in-flight / Sparkle pending quit share this flag). Worst uncovered
    // race degrades a clean quit to the agent's grace-end force-quit — the designed fail-safe.
    if (self.quittingMyself) return;
    // 6. Display actually awake (F6): a lid flap that re-slept before we got here spends nothing.
    if (CGDisplayIsAsleep(CGMainDisplayID())) return;
    // Rate limit (own budget — never the ladder's counter, F6).
    if (_bweLastNudgeAt > 0 && (nowT - _bweLastNudgeAt) < kBWENudgeMinInterval) return;
    _bweLastNudgeAt = nowT;
    _bweWakeOrdinal++;

    // Rung 1 — nudge, always: the two jitter lines ONLY, applied to every SEBBrowserWindow's
    // nativeWebView (main + site windows — the §1.4 sweep). Explicitly NOT blinkeredNudgeWindow /
    // blinkeredFocusMainContent: — no activate, no makeKey, no reordering (review F3: those
    // visibly raise the lock page over the kid's site window on every wake).
    for (NSWindow *win in [NSApp windows]) {
        if (![win isKindOfClass:[SEBBrowserWindow class]]) continue;
        id abstract = [win valueForKey:@"webView"];
        if (abstract && [abstract respondsToSelector:@selector(nativeWebView)]) {
            NSView *wv = [abstract performSelector:@selector(nativeWebView)];
            if ([wv isKindOfClass:[NSView class]]) {
                NSRect fr = wv.frame; wv.frame = NSInsetRect(fr, 0, 1); wv.frame = fr; [wv setNeedsDisplay:YES];
            }
        }
    }
    DDLogInfo(@"Blinkered wake-edge: nudged (wake #%ld) — probing in %.1fs", (long)_bweWakeOrdinal, kBWESettle);

    // Rung 2 — probe after settle, on the wedged-WebContent signals only (§1.4/§1.5).
    double wakeEpochMs = [[NSDate date] timeIntervalSince1970] * 1000.0;
    NSInteger ordinal = _bweWakeOrdinal;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kBWESettle * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self blinkeredWakeEdgeProbeWithWakeEpochMs:wakeEpochMs startedAt:nowT ordinal:ordinal isRetry:NO];
    });
}

// One takeSnapshot liveness attempt with a deadline. Completion fires EXACTLY once, on the main
// queue: 'ok'/'error' when WebContent answers in time, 'timeout' when it does not — the fault
// signal itself (a wedged WebContent never calls the completion handler; CORRECTION §New-ground-
// truth). Late answers after the deadline are discarded (double-fire guard, F2). The tiny corner
// rect makes this a render-path probe, not imagery: nothing is stored or transmitted.
- (void)blinkeredWakeSnapshotProbe:(WKWebView *)wk completion:(void (^)(NSString *verdict, NSInteger ms))completion {
    NSTimeInterval start = [NSDate timeIntervalSinceReferenceDate];
    __block BOOL settled = NO;
    WKSnapshotConfiguration *cfg = [WKSnapshotConfiguration new];
    cfg.rect = NSMakeRect(0, 0, MIN(64.0, wk.bounds.size.width), MIN(64.0, wk.bounds.size.height));
    [wk takeSnapshotWithConfiguration:cfg completionHandler:^(NSImage *img, NSError *err) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (settled) return;
            settled = YES;
            completion(err ? @"error" : @"ok", (NSInteger)(([NSDate timeIntervalSinceReferenceDate] - start) * 1000.0));
        });
    }];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kBWEProbeDeadline * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (settled) return;
        settled = YES;
        completion(@"timeout", (NSInteger)(kBWEProbeDeadline * 1000.0));
    });
}

// rAF-stamp read with the SAME deadline treatment as the snapshot (F2: evaluateJavaScript's
// completion also never arrives from a wedged WebContent). Four outcomes:
//   advanced — stamp is a number ≥ the wake wall-time (page composited since the wake; healthy)
//   stalled  — stamp readable but pre-wake (rAF frozen through sleep is NORMAL; stalled only
//              means "not yet" — it corroborates a wedge ONLY alongside a snapshot timeout)
//   nosignal — completed with a non-number (page never loaded / offline error page). NEVER a
//              reload trigger on its own (F2/F5).
//   timeout  — eval never answered: the same wedge signal as a snapshot timeout.
- (void)blinkeredWakeRafProbe:(WKWebView *)wk wakeEpochMs:(double)wakeEpochMs completion:(void (^)(NSString *state))completion {
    __block BOOL settled = NO;
    [wk evaluateJavaScript:@"window.__blinkeredLastPaint || 0" completionHandler:^(id res, NSError *err) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (settled) return;
            settled = YES;
            if (err || ![res isKindOfClass:[NSNumber class]] || [res doubleValue] <= 0) { completion(@"nosignal"); return; }
            completion([res doubleValue] >= wakeEpochMs ? @"advanced" : @"stalled");
        });
    }];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kBWEProbeDeadline * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (settled) return;
        settled = YES;
        completion(@"timeout");
    });
}

- (void)blinkeredWakeEdgeProbeWithWakeEpochMs:(double)wakeEpochMs startedAt:(NSTimeInterval)startedAt
                                      ordinal:(NSInteger)ordinal isRetry:(BOOL)isRetry {
    WKWebView *wk = [self blinkeredMainWebView];
    if (!wk) {
        [self blinkeredReportWakeNudge:@"skipped" snapshotMs:0 raf:@"nosignal" reloadRan:NO startedAt:startedAt ordinal:ordinal];
        return;
    }
    __block NSString *rafState = nil;
    __block NSString *snapVerdict = nil;
    __block NSInteger snapMs = 0;
    void (^judge)(void) = ^{
        if (!rafState || !snapVerdict) return;   // wait for both probes
        // Impl-review fast-follow (MINOR 1+2): the probe chain runs up to ~11s past the wake edge,
        // so re-check the gates that can flip mid-chain. (1) An overdue unlock is delivered on the
        // wake polls — the motivating incident's own timeline — so quit/teardown and session state
        // must be re-checked at VERDICT time, not only at the edge. (2) A lid flap that slept and
        // re-woke inside the probe window produces a sleep-starved snapshot timeout on a healthy
        // device — a NEW wake edge mid-chain (its own recovery pass is coming) discards this one.
        if (self.quittingMyself || ![self blinkeredPaintLockActive]) {
            DDLogInfo(@"Blinkered wake-edge: quit/session state changed mid-probe — verdict discarded");
            return;
        }
        if (_blinkeredLastWakeAt > startedAt) {
            DDLogInfo(@"Blinkered wake-edge: new wake edge mid-probe — verdict discarded (no budget spent)");
            return;
        }
        // Snapshot timeout gets ONE retry (Q1): a just-woken compositor can legitimately miss the
        // first deadline, and a false timeout now costs a budget slot.
        if ([snapVerdict isEqualToString:@"timeout"] && !isRetry) {
            DDLogInfo(@"Blinkered wake-edge: snapshot timed out — one retry");
            [self blinkeredWakeEdgeProbeWithWakeEpochMs:wakeEpochMs startedAt:startedAt ordinal:ordinal isRetry:YES];
            return;
        }
        // Discard the verdict entirely if the display re-slept mid-probe (F6): nobody is looking,
        // and a starved WebContent under a dark panel is not a fault. No budget spent.
        if (CGDisplayIsAsleep(CGMainDisplayID())) {
            DDLogInfo(@"Blinkered wake-edge: display re-slept mid-probe — verdict discarded");
            return;
        }
        // Reload iff snapshot timed out AND the stamp did not advance since the wake — where
        // "did not advance" means stalled-readable or eval-timeout, NEVER nosignal (F2/F5).
        BOOL wedged = [snapVerdict isEqualToString:@"timeout"]
            && ([rafState isEqualToString:@"stalled"] || [rafState isEqualToString:@"timeout"]);
        BOOL reloadRan = NO;
        // CONDITION 5 / review F11 scenario A. `![self blinkeredNavigationInFlight]` is the new
        // clause: with Fix 2 shipping there are two independent navigators, and this probe chain
        // runs up to ~11 s. A Fix 2 retry issued 3 s into it leaves the page mid-load, which is
        // exactly what makes the snapshot and rAF probes time out — so without this the wake edge
        // would read a healthy recovering device as wedged, load ON TOP of the retry, and spend a
        // kBWEMaxReloadsSession slot doing it. The panel bail beside it is UNCHANGED: this line
        // does not touch it, and §4.1's "delete the panel bail" is about the bail Fix 2 was asked
        // to ADD, never this shipped one.
        if (wedged && !_blinkeredOfflinePanelShowing && ![self blinkeredNavigationInFlight]
            && _bweSessionReloads < kBWEMaxReloadsSession) {
            // load(url), NOT reload() — the abstract reload wipes the WK caches first (F5), and the
            // wedge hypothesis is a dead WebContent, not stale cache. Same-webview load keeps every
            // SEB navigation-policy hook in the path.
            // Same selection as the offline panel's Retry (OFFLINE_RETRY_DEAD_END_PLAN §3 C4):
            // the committed URL only when it is one of ours over https, else the configured start
            // URL. A bare `target = wk.URL` was wrong in the same way Retry was — on a device
            // showing the offline cover that URL is about:blank, so a wedge recovery would have
            // turned a correctly covered lock into a permanently blank one. This also retires the
            // last bare read of the startURL pref: blinkeredConfiguredStartURL reproduces the
            // startURLAppendQueryParameter append, so what we navigate and what the interceptors
            // authorise are now one function of one input (§3.1).
            NSURL *target = [SEBAbstractWebView blinkeredRecoveryTargetForCommittedURL:wk.URL
                                                                    configuredStartURL:[SEBAbstractWebView blinkeredConfiguredStartURL]];
            if (target) {
                _bweSessionReloads++;
                reloadRan = YES;
                DDLogWarn(@"Blinkered wake-edge: WebContent wedged (snapshot timeout + rAF %@) — reloading lock page (%ld/%ld this session)",
                          rafState, (long)_bweSessionReloads, (long)kBWEMaxReloadsSession);
                [self blinkeredIssueRecoveryNavigation:target webView:wk];
            }
        }
        [self blinkeredReportWakeNudge:snapVerdict snapshotMs:snapMs raf:rafState reloadRan:reloadRan startedAt:startedAt ordinal:ordinal];
    };
    [self blinkeredWakeSnapshotProbe:wk completion:^(NSString *verdict, NSInteger ms) {
        snapVerdict = verdict; snapMs = ms; judge();
    }];
    // On the retry round the rAF stamp is deliberately re-read: a wedge can resolve between rounds,
    // and the verdict must reflect the state the retry actually judged.
    [self blinkeredWakeRafProbe:wk wakeEpochMs:wakeEpochMs completion:^(NSString *state) {
        rafState = state; judge();
    }];
}

// §1.7 telemetry: one labelled experiment per acted-on wake edge, on its OWN kind (F7 — never
// paint_fault, so flip queries can't mix artifact/probe/action rows). snapshotVerdict scopes what
// the probe saw: the WebContent process, not the glass (§1.5) — 'ok' does not mean "not black".
- (void)blinkeredReportWakeNudge:(NSString *)snapVerdict snapshotMs:(NSInteger)snapMs raf:(NSString *)rafState
                       reloadRan:(BOOL)reloadRan startedAt:(NSTimeInterval)startedAt ordinal:(NSInteger)ordinal {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[dirs firstObject] stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    NSData *cd = [NSData dataWithContentsOfFile:agentJson];
    NSDictionary *creds = cd ? [NSJSONSerialization JSONObjectWithData:cd options:0 error:nil] : nil;
    if (![creds isKindOfClass:[NSDictionary class]]) return;
    NSString *devId = creds[@"id"], *devTok = creds[@"token"];
    NSString *server = [creds[@"server"] isKindOfClass:[NSString class]] ? creds[@"server"] : @"https://blinkered.com.au";
    if (![devId isKindOfClass:[NSString class]] || ![devTok isKindOfClass:[NSString class]]) return;
    BOOL lpm = NO;
    if (@available(macOS 12.0, *)) { lpm = NSProcessInfo.processInfo.isLowPowerModeEnabled; }
    NSString *appVer = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSMutableDictionary *body = [@{ @"token": devTok, @"kind": @"wake_nudge",
        @"exceptionType": @"WakeNudge", @"method": @"wake",
        @"appVersion": appVer, @"os": ([[NSProcessInfo processInfo] operatingSystemVersionString] ?: @""),
        @"snapshotVerdict": (snapVerdict ?: @"skipped"), @"snapshotMs": @(snapMs),
        @"reloadRan": @(reloadRan), @"displaySlept": @YES, @"lpm": @(lpm),
        @"budgetReloadsUsed": @(_bweSessionReloads), @"wakeOrdinal": @(ordinal),
        @"msSinceWake": @((NSInteger)(([NSDate timeIntervalSinceReferenceDate] - startedAt) * 1000.0)) } mutableCopy];
    // rafReadable/rafAdvanced tri-state: nosignal → readable NO (advanced omitted → null server-side);
    // timeout → both omitted (null: the read itself never answered — that's the snapshot's story).
    if ([rafState isEqualToString:@"advanced"] || [rafState isEqualToString:@"stalled"]) {
        body[@"rafReadable"] = @YES;
        body[@"rafAdvanced"] = @([rafState isEqualToString:@"advanced"]);
    } else if ([rafState isEqualToString:@"nosignal"]) {
        body[@"rafReadable"] = @NO;
    }
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/home/devices/%@/crash-report", server, devId]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    [[[NSURLSession sharedSession] dataTaskWithRequest:req] resume];
    DDLogInfo(@"Blinkered wake_nudge: snapshot=%@ (%ldms) raf=%@ reload=%d wake#%ld", snapVerdict, (long)snapMs, rafState, reloadRan, (long)ordinal);
}

// ── Blinkered Home: background polling agent ──────────────────────────────────

// Stable per-Mac hardware id (IOPlatformUUID) — survives reinstalls/re-pairs, so the server can
// recognise the same Mac and replace its old device record instead of creating a ghost.
- (NSString *)blinkeredHardwareUUID {
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (!svc) return nil;
    CFTypeRef cf = IORegistryEntryCreateCFProperty(svc, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
    IOObjectRelease(svc);
    if (!cf) return nil;
    NSString *uuid = (__bridge_transfer NSString *)cf;
    return uuid.length ? uuid : nil;
}

- (void)blinkeredHandleSavePair:(NSURL *)url {
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    NSString *deviceId = nil, *token = nil, *server = @"https://blinkered.com.au", *mode = nil;
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:@"id"])     deviceId = item.value;
        if ([item.name isEqualToString:@"token"])  token    = item.value;
        if ([item.name isEqualToString:@"server"]) server   = item.value;
        if ([item.name isEqualToString:@"mode"])   mode     = item.value;   // P1-2: 'cooperative' | 'enforced' | (absent = legacy)
    }
    if (!deviceId.length || !token.length) {
        DDLogError(@"Blinkered: savepair URL missing id or token — ignoring");
        return;
    }

    // Persist credentials for the background agent
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *appSupportDirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *dir = [[appSupportDirs firstObject] stringByAppendingPathComponent:@"Blinkered"];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    // The setup mode used to ride the ?mode= URL param alone, which only survives the ONE
    // /pair?mode=enforced window the app opens itself — every other pairing path (dashboard
    // email/code, re-pair, an already-paired device) drops it and defaults Cooperative, so Enforced
    // was in practice unreachable. Fix: derive the mode from an AUTHORITATIVE on-disk observation the
    // app can always read, at savepair — the choke point every pairing funnels through.
    //
    // The .pkg (the Enforced installer) is the ONLY thing that writes this LaunchDaemon plist, so its
    // presence IS "this is an Enforced device". Same check as blinkeredDoBareLaunchRedirect above.
    // pkg present => enforced; otherwise fall back to the URL hint, else cooperative. The URL param is
    // kept as belt-and-braces (it just can't be the sole signal any more).
    BOOL pkgEnforced = [[NSFileManager defaultManager]
        fileExistsAtPath:@"/Library/LaunchDaemons/app.blinkered.updater.plist"];
    NSString *effectiveMode = pkgEnforced ? @"enforced" : (mode.length ? mode : @"cooperative");

    // Persist effectiveMode — overriding whatever the URL carried — so blinkeredPersistedMode and the
    // agent both see the observed truth, not the lossy URL hint.
    NSMutableDictionary *creds = [@{@"id": deviceId, @"token": token, @"server": server, @"mode": effectiveMode} mutableCopy];
    NSData *data = [NSJSONSerialization dataWithJSONObject:creds options:NSJSONWritingPrettyPrinted error:nil];
    [data writeToFile:[dir stringByAppendingPathComponent:@"agent.json"] atomically:YES];
    DDLogInfo(@"Blinkered: saved pair credentials for device %@ (mode=%@ url-hint=%@ pkg=%d)",
              deviceId, effectiveMode, mode ?: @"(none)", pkgEnforced);

    // P1-2: Cooperative must have NO root component — if a prior flow (or an Enforced->Cooperative re-pair)
    // left an SMAppService updater registered, tear it down now. Keyed on the OBSERVED effectiveMode:
    // when the pkg daemon is present we're Enforced and must NOT touch it (blinkeredRetireSMAppServiceUpdater
    // early-returns on the pkg plist anyway, and only ever de-registers the SMAppService variant).
    if ([effectiveMode isEqualToString:@"cooperative"]) {
        [self blinkeredRetireSMAppServiceUpdater];
    }

    // Re-pair = replace: report this Mac's stable hardware id so the server removes any earlier
    // pairing of the SAME Mac (no ghost device records). Best-effort + short timeout — the app quits
    // right after savepair, so we wait briefly but never block pairing if the network is slow.
    NSString *hwid = [self blinkeredHardwareUUID];
    if (hwid.length) {
        NSURL *hwURL = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/home/devices/%@/hardware", server, deviceId]];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:hwURL];
        req.HTTPMethod = @"POST";
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        // Carry the observed mode too: this POST reaches the server on EVERY pairing path (unlike the
        // redeem-time ?mode=, which most paths lose), so it's the authoritative tag/confirm. The server
        // validates it and updates home_devices.mode. Cooperative is unaffected (a DMG install has no
        // pkg plist -> declares cooperative, which is the default anyway).
        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"token": token, @"hardwareId": hwid, @"mode": effectiveMode} options:0 error:nil];
        req.timeoutInterval = 3.0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            if (e) { DDLogError(@"Blinkered: hardware-id report failed: %@", e); }
            else   { DDLogInfo(@"Blinkered: reported hardware id (re-pair replace)"); }
            dispatch_semaphore_signal(sem);
        }] resume];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.5 * NSEC_PER_SEC)));
    }

    [self blinkeredInstallLaunchAgent];

    // Mark as handled so applicationDidFinishLaunching: quits cleanly.
    _blinkeredSavePair = YES;
    _openedURL = YES;
}

// launchd job label for the background agent. One spelling, used by every launchctl target below.
static NSString * const kBlinkeredAgentLabel = @"app.blinkered.agent";

// THE DISCRIMINATOR (C4). `launchctl print` emits this line for a job that was SUBMITTED by a client
// process (`launchctl load`) and omits it for one ESTABLISHED in the domain (`launchctl bootstrap`).
// A submitted job is not re-created from ~/Library/LaunchAgents when the domain is rebuilt at login;
// an established one is. Measured on macOS 26.6.1: present exactly once on a load-ed job, and the
// substring "submit" does not occur at all in a bootstrap-ed job's print output.
//
// Presence in the domain is NOT the property, and neither is liveness. A broken device is present
// AND live: on Poppy's Mac, before its logout, `print` exited 0 and `list` showed a PID. Branching on
// the status alone answers a question nobody asked.
static NSString * const kBlinkeredLaunchdSubmittedMarker = @"submitted job";

// C11. The launchd job's program, which must live OUTSIDE the app bundle — see the long note in
// blinkeredInstallLegacyLaunchAgent for the device evidence. /bin/zsh is what com.blinkered.shieldloop
// uses, and shieldloop is the job that survived every cycle that killed ours.
static NSString * const kBlinkeredAgentLauncher = @"/bin/zsh";

// C11a — `-f` (NO_RCS). NOT cosmetic, and NOT removable.
//
// `zsh -c` sources ~/.zshenv. Measured: with `exec /bin/sleep 86400` in ~/.zshenv, the job's pid runs
// /bin/sleep and the agent never starts — so a standard, non-admin child account disables the product
// permanently, from a file in its own home directory, with no privileges. And undetectably: every
// term of the no-op reads healthy, because `wasRunning` was reading the JOB's pid, which is sleep's.
// The repair never fires, nothing is reported, and opening Blinkered.app — the documented recovery —
// does not repair it.
//
// That is strictly worse than the `launchctl bootout` a child could already do, which is
// session-scoped, leaves no PID (so the next launch repairs it), and fires agent_repaired.
//
// Measured: `-f` skips ~/.zshenv AND preserves the positional-argument design.
static NSString * const kBlinkeredAgentLauncherNoRCFlag = @"-f";

// The canonical ProgramArguments for the agent job. ONE definition, used by the installer to write
// the plist and by the migration check to validate it, so the two can never disagree about what a
// correct plist looks like.
//
// C11b — the migration check compares this WHOLE array. Checking only args[0] == "/bin/zsh" accepts a
// plist whose agent path points at a bundle that no longer exists — and because the spin guard keeps
// the wrapper alive forever, that state holds a live PID and reads healthy indefinitely. That is a
// REGRESSION against the pre-C11 code, where Program was the agent binary itself: a stale path meant
// no process, so wasRunning was NO, so the repair fired. Reachable through the installer-DMG flow
// (blinkeredEjectInstallerDMG exists because that flow is real), Gatekeeper app translocation, and a
// user simply moving the app.
//
// The agent path is $1, a positional argument, never interpolated into the script — so no shell
// quoting exists to get wrong on a path containing a space or an apostrophe.
- (NSArray<NSString *> *)blinkeredAgentProgramArgumentsFor:(NSString *)agentBinary {
    return @[kBlinkeredAgentLauncher,
             kBlinkeredAgentLauncherNoRCFlag,
             @"-c",
             // The spin guard. With KeepAlive, a shell that exits because the binary is briefly
             // missing — which it is on every Sparkle update — is relaunched forever. Wait instead.
             @"while :; do if [ -x \"$1\" ]; then exec \"$1\"; fi; sleep 10; done",
             @"blinkered-agent-launcher",
             agentBinary];
}

// G5 — the canonical plist, WHOLE. C11b validated ProgramArguments; that is one key of six.
// `RunAtLoad: NO` leaves ProgramArguments byte-identical and every other term reads healthy — the job
// simply never starts at login. Measured: the args-only comparison does not notice, the whole-dict
// comparison does. Not a regression and it needs deliberate tampering, but C11b's framing implies
// plist integrity is covered, so cover it.
//
// Verified that a write/read round trip compares equal with isEqualToDictionary:, so this cannot
// false-positive into repairing on every launch.
- (NSDictionary *)blinkeredAgentPlistFor:(NSString *)agentBinary logPath:(NSString *)logPath {
    return @{
        @"Label": kBlinkeredAgentLabel,
        @"ProgramArguments": [self blinkeredAgentProgramArgumentsFor:agentBinary],
        @"RunAtLoad": @YES,
        @"KeepAlive": @YES,
        @"StandardOutPath": logPath,
        @"StandardErrorPath": logPath,
    };
}

// launchctl exit statuses, established by measurement rather than assumed:
//   bootout on a service that is not there    -> 3   ("Boot-out failed: 3: No such process")
//   bootstrap of a label already bootstrapped -> 5   ("Bootstrap failed: 5: Input/output error")
//   bootstrap with a missing plist            -> 5   (same code — 5 is ambiguous, never trusted)
//   print / list of an absent service         -> 113
static const int kBlinkeredLaunchctlNoSuchProcess = 3;
static const int kBlinkeredLaunchctlAlreadyBootstrapped = 5;
// Our own sentinels for "the subprocess did not produce an answer" (C9). Negative so they can never
// collide with a real launchctl status.
static const int kBlinkeredLaunchctlCouldNotRun = -1;
static const int kBlinkeredLaunchctlTimedOut    = -2;
// `launchctl print` measures at <10 ms. Ten seconds is not a tuning parameter, it is a deadlock stop.
static const NSTimeInterval kBlinkeredLaunchctlTimeout = 10.0;

// C4/C9 tri-state. "Unknown" is NOT a synonym for "broken": it means the probe could not answer, and
// per C9 it must never authorise a destructive repair of a live agent.
typedef NS_ENUM(NSInteger, BlinkeredAgentEstablishment) {
    BlinkeredAgentEstablishmentUnknown = 0,   // the probe could not run, timed out, or said nothing
    BlinkeredAgentEstablishmentAbsent,        // not in the GUI domain at all (print -> 113)
    BlinkeredAgentEstablishmentSubmitted,     // present but load-ed — will NOT survive a login
    BlinkeredAgentEstablishmentEstablished,   // present and bootstrap-ed — survives a login
};

// H3 — liveness is a TRI-STATE too, for the same reason establishment is: "the probe could not
// answer" is not "the agent is dead". Which way an unanswerable probe should fall depends entirely on
// the CONSUMER, so the probe must not decide for them:
//   • as `wasRunning` in the no-op condition, falling to NO is fail-SAFE — it repairs a healthy device
//     unnecessarily, which costs a restart.
//   • as `agentAlive` in C13, falling to NO is fail-DANGEROUS — it authorises bootout -> agent restart
//     -> cold-launch -> SIGKILL on a child's live kiosk, which is the exact harm C13 exists to prevent.
// So C13 treats Unknown as "defer", inverting the default that a plain BOOL would have forced on it.
typedef NS_ENUM(NSInteger, BlinkeredAgentLiveness) {
    BlinkeredAgentLivenessUnknown = 0,   // ps could not be run, timed out, or failed
    BlinkeredAgentLivenessDead,          // ps answered, and this user has no agent process
    BlinkeredAgentLivenessAlive,         // ps answered, and this bundle's agent is running as this uid
};

// One repair per app launch (C10). The repair restarts the agent, and a restarted agent cold-launches
// a live lock — a kill dance that escalates to SIGKILL on a child's running kiosk. The health check
// is scheduled ONCE per app launch (a single dispatch_after at +20 s — not a repeating timer), so the
// bound this latch adds is per-launch, on top of that. Latched here, not inside the install: the
// savepair path calls the install
// DIRECTLY as a deliberate first-pairing restart, and that is not "the repair".
static BOOL _blinkeredAgentRepairAttempted = NO;

// The per-user GUI domain: gui/<uid>. Derived from getuid() and NEVER assumed to be 501 — a
// standard kid account on a family Mac is not uid 501, and hard-coding it would silently target
// someone else's session (or nothing at all).
- (NSString *)blinkeredGUIDomainTarget {
    return [NSString stringWithFormat:@"gui/%u", getuid()];
}

// The service target for our agent inside that domain: gui/<uid>/app.blinkered.agent.
- (NSString *)blinkeredAgentServiceTarget {
    return [NSString stringWithFormat:@"%@/%@", [self blinkeredGUIDomainTarget], kBlinkeredAgentLabel];
}

// Runs /bin/launchctl and returns its exit status, with stdout and stderr MERGED into `output`.
// Returns kBlinkeredLaunchctlCouldNotRun / kBlinkeredLaunchctlTimedOut when there is no answer.
//
// stderr is merged deliberately: launchctl reports the interesting part of a failure there, and the
// legacy `load` subcommand reports failure ONLY there (it exits 0 regardless). Every caller must
// branch on the returned status — capturing an outcome and then asserting a different one is the
// defect this whole change exists to remove.
//
// C9: BOUNDED. This runs on the launch path of every paired Mac. The pipe is drained on a background
// queue and the wait is on a deadline, so neither a wedged launchctl nor a full pipe can hang the
// caller. A timeout returns its own status precisely so callers can tell "not established" (a fact
// about the device) from "no answer" (a fact about the probe) — only the first may authorise a
// destructive repair.
- (int)blinkeredRunLaunchctl:(NSArray<NSString *> *)args output:(NSString **)output {
    return [self blinkeredRunTool:@"/bin/launchctl" args:args output:output];
}

// H3 — the bounded runner, generalised. C9 was written as a principle ("bound the subprocess, and
// never let a probe ERROR trigger a destructive repair") and then applied to exactly one method.
// blinkeredAgentProcessAlive: runs on the launch path of every paired Mac, twice per repair pass, and
// had no deadline and no tri-state at all. Same treatment, one implementation.
- (int)blinkeredRunTool:(NSString *)launchPath args:(NSArray<NSString *> *)args output:(NSString **)output {
    if (output) { *output = @""; }
    NSTask *task = [NSTask new];
    task.launchPath = launchPath;
    task.arguments = args;
    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;
    NSFileHandle *readEnd = [pipe fileHandleForReading];
    __block NSData *collected = nil;
    dispatch_semaphore_t drained = dispatch_semaphore_create(0);
    @try {
        // Drain on a background queue: the read completes when every write end closes, which is the
        // child exiting. Reading inline would block past any deadline we set.
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            @try { collected = [readEnd readDataToEndOfFile]; }
            @catch (__unused NSException *e) { collected = nil; }
            dispatch_semaphore_signal(drained);
        });
        [task launch];
        if (dispatch_semaphore_wait(drained, dispatch_time(DISPATCH_TIME_NOW,
                                    (int64_t)(kBlinkeredLaunchctlTimeout * NSEC_PER_SEC))) != 0) {
            @try { [task terminate]; } @catch (__unused NSException *e) {}
            DDLogError(@"Blinkered: %@ %@ TIMED OUT after %.0fs — treating as no answer, not as a verdict",
                       launchPath, [args componentsJoinedByString:@" "], kBlinkeredLaunchctlTimeout);
            if (output) { *output = @"tool timed out"; }
            return kBlinkeredLaunchctlTimedOut;
        }
        [task waitUntilExit];
        if (output) {
            NSString *text = collected ? [[NSString alloc] initWithData:collected encoding:NSUTF8StringEncoding] : nil;
            *output = [(text ?: @"") stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        }
        return task.terminationStatus;
    } @catch (NSException *e) {
        if (output) { *output = e.reason ?: @"tool could not be run"; }
        return kBlinkeredLaunchctlCouldNotRun;
    }
}

// C4: ESTABLISHMENT, not presence, and not liveness. Reads `print`'s OUTPUT, not just its status —
// the first implementation of this fetched the output into a variable and then used it only for
// logging, so the code was blind to the one thing it had already gone and fetched.
//
// Needs no elevated privileges: exit 0 when present, 113 when absent. Measured, both ways, as an
// ordinary user.
- (BlinkeredAgentEstablishment)blinkeredAgentEstablishment {
    NSString *out = nil;
    int status = [self blinkeredRunLaunchctl:@[@"print", [self blinkeredAgentServiceTarget]] output:&out];

    if (status == kBlinkeredLaunchctlTimedOut || status == kBlinkeredLaunchctlCouldNotRun) {
        DDLogError(@"Blinkered: agent establishment UNKNOWN — the probe could not run (status %d: %@)", status, out);
        return BlinkeredAgentEstablishmentUnknown;
    }
    if (status != 0) {
        DDLogInfo(@"Blinkered: agent ABSENT from %@ (launchctl print status %d: %@)",
                  [self blinkeredGUIDomainTarget], status, out);
        return BlinkeredAgentEstablishmentAbsent;
    }
    // Exit 0 but nothing captured: we cannot tell submitted from established, so we must NOT guess
    // "established". Guessing healthy on a silent probe is how a check becomes vacuous.
    if (out.length == 0) {
        DDLogError(@"Blinkered: agent establishment UNKNOWN — print exited 0 with no output");
        return BlinkeredAgentEstablishmentUnknown;
    }
    if ([out containsString:kBlinkeredLaunchdSubmittedMarker]) {
        DDLogInfo(@"Blinkered: agent is present in %@ but SUBMITTED, not established — it will NOT "
                  @"survive the next login", [self blinkeredGUIDomainTarget]);
        return BlinkeredAgentEstablishmentSubmitted;
    }
    return BlinkeredAgentEstablishmentEstablished;
}

- (NSString *)blinkeredLegacyLaunchAgentPath {
    NSArray *libraryDirs = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    return [[[libraryDirs firstObject] stringByAppendingPathComponent:@"LaunchAgents"]
        stringByAppendingPathComponent:@"app.blinkered.agent.plist"];
}

// (F10) blinkeredRemoveLegacyLaunchAgent was deleted here. It had no callers — it belonged to the
// retired design in which SMAppService was PRIMARY and the ~/Library/LaunchAgents copy was the thing
// to remove. That polarity is now inverted, so its doc comment actively misdescribed the system, and
// pinning dead code in a gate buys nothing. The SMAppService retirement that IS still needed lives in
// blinkeredInstallLegacyLaunchAgent, where it runs.

- (void)blinkeredInstallLaunchAgent {
    [self blinkeredInstallLaunchAgentReportRepair:NO];
}

// Install / repair the background agent. The PRIMARY mechanism is the plain
// ~/Library/LaunchAgents/app.blinkered.agent.plist login item: launchd scans that directory at
// EVERY login, so the agent self-recovers across logout, fast-user-switch, and OS updates — the
// failures where SMAppService's managed background-item registration was silently DROPPED, leaving
// the device unlockable until someone manually opened the app (seen on-device 10 Jul 2026: a
// logout/login lost the registration entirely; launchctl reported "Could not find service"). The
// only thing we give up vs SMAppService is a cosmetic "attributed to Blinkered" label in Login
// Items; for a security control, reliably running matters far more.
//
// Idempotent: if the plist is present AND the agent is running AND log-current AND ESTABLISHED in
// the GUI domain (C7 — "present in the domain" is not the property that matters, and is implied by
// running anyway), this no-ops — so
// it's safe to call on every launch and on every bare-launch / health-check pass (a ~50ms
// launchctl-list check). reportRepair:YES means "this device is already paired, so the agent was
// EXPECTED to be running": if it was in fact missing and we brought it back, tell the parent
// (agent_repaired). First install / pairing passes NO (a fresh install isn't a repair).
- (void)blinkeredInstallLaunchAgentReportRepair:(BOOL)reportRepair {
    NSString *agentBinary = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Contents/MacOS/BlinkeredAgent"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:agentBinary]) {
        DDLogError(@"Blinkered: BlinkeredAgent not found at %@ — cannot install LaunchAgent", agentBinary);
        return;
    }
    NSString *plistPath = [self blinkeredLegacyLaunchAgentPath];
    BOOL plistPresent = [[NSFileManager defaultManager] fileExistsAtPath:plistPath];
    // "Loaded" is not enough: a crashing agent stays REGISTERED with launchd (PID '-', last exit 78)
    // yet enforces nothing. Require it to be actually RUNNING. Also treat an out-of-date log path (an
    // old shared-/tmp plist) as needs-repair, so every Mac migrates to the per-user log on next launch.
    BOOL wasRunning = [self blinkeredAgentRunningWithin:0.1];
    BOOL logCurrent = plistPresent && [self blinkeredPlistUsesCurrentLogPath:plistPath];
    // C11 MIGRATION. A bundle-resident job can be running AND established AND log-current and still
    // vanish at the next login — that is precisely what was measured on Maggie's Mac on 21 Aug. So
    // "reaches the agent through the out-of-bundle launcher" is its own term, and it is the one that
    // decides whether this device comes back. False on every deployed Mac, so the repair fires once
    // on each and rewrites the plist.
    BOOL launcherCurrent = plistPresent && [self blinkeredPlistIsCanonical:plistPath];

    // C7 MIGRATION — the fourth term is ESTABLISHMENT, and it must not be "present in the domain".
    //
    // The first version of this condition used "registered in the GUI domain" and claimed that
    // running-but-wrongly-registered would now fail it. That was FALSE, and provably so from a
    // measurement this workstream already had: `wasRunning` is `launchctl list <label>` matching
    // "PID", and a job with a live PID in the caller's domain necessarily satisfies
    // `print gui/<uid>/<label>`. So wasRunning IMPLIED registered, the fourth term was a tautology
    // inside the conjunction, and the no-op fired on exactly the broken fleet state. The migration
    // would have reached zero devices while looking indistinguishable from a pass.
    //
    // `established` is false on every currently-broken device (marker present) and true after a real
    // bootstrap, so the term now carries information. ~10 ms, no privileges.
    BlinkeredAgentEstablishment establishment = plistPresent ? [self blinkeredAgentEstablishment]
                                                            : BlinkeredAgentEstablishmentAbsent;
    BOOL established = (establishment == BlinkeredAgentEstablishmentEstablished);
    if (plistPresent && wasRunning && logCurrent && established && launcherCurrent) {
        // DDLogInfo, NOT DDLogVerbose. Verified against DDLog.h: DDLogFlagVerbose is (1 << 4) and
        // DDLogLevelDebug is 0…01111, so the Verbose bit is UNSET at the level this app sets
        // (SEBController.m:1111). As DDLogVerbose this line was never written at all — and runbook
        // §0.5 steps 5 and 5b, the convergence checks this whole round exists for, score on seeing it.
        // Worse, its absence is ambiguous: "no installing/repairing" is equally what a C9 defer and a
        // C10 latch produce, so a probe failure would have been recorded as convergence.
        DDLogInfo(@"Blinkered: LaunchAgent installed, running, log-path current, ESTABLISHED, "
                  @"out-of-bundle launcher — no-op");
        return;   // healthy — nothing to do (and don't restart a live agent mid-lock)
    }

    // C9 — a probe that could not ANSWER must never authorise a destructive repair. The repair boots
    // a live agent out; doing that because launchctl timed out would take a healthy device down on
    // the strength of no information at all. "Unknown" is not "broken". Only a definitive negative
    // (Submitted or Absent) may bootout something live; if the agent is already dead there is nothing
    // to lose and the repair proceeds regardless of what the probe managed to say.
    if (wasRunning && establishment == BlinkeredAgentEstablishmentUnknown && launcherCurrent) {
        DDLogError(@"Blinkered: agent is RUNNING but its establishment could not be determined — "
                   @"declining to bootout a live agent on no information. Re-checking next launch.");
        return;
    }
    // Note the `&& launcherCurrent` above. C9 says a probe that cannot ANSWER must not authorise a
    // destructive repair — but the C11 term is a file read, not a probe, so it is knowable even when
    // launchctl is wedged. A bundle-resident plist is a definitive negative on the property that
    // actually decides survival, so it justifies the repair on its own. Without this qualifier a Mac
    // whose probe kept failing would sit bundle-resident forever, which is the state we are fixing.

    // C10 — at most one repair per app launch. The repair restarts the agent, and a restarted agent
    // treats a live lock as new and cold-launches it, killing the child's running kiosk on the way.
    // The health check is ONE-SHOT per app launch (a single dispatch_after at +20 s), so a deferral
    // or a failure here does not retry in 20 s — it waits for the NEXT LAUNCH. That is what a
    // "DEFERRED" line in the log means, and the runbook says so. This latch bounds the other axis:
    // the repair restarts the agent, which relaunches Blinkered, which is a new process — so latch it
    // even when the repair FAILS, because a repair that cannot succeed is exactly the one that loops.
    if (_blinkeredAgentRepairAttempted) {
        DDLogWarn(@"Blinkered: LaunchAgent repair already attempted this launch (plist:%d running:%d "
                  @"logCurrent:%d established:%d launcherCurrent:%d) — not repeating it; see C10.",
                  plistPresent, wasRunning, logCurrent, established, launcherCurrent);
        return;
    }
    _blinkeredAgentRepairAttempted = YES;

    DDLogInfo(@"Blinkered: installing/repairing LaunchAgent (plist:%d running:%d logCurrent:%d "
              @"establishment:%ld launcherCurrent:%d)",
              plistPresent, wasRunning, logCurrent, (long)establishment, launcherCurrent);
    // C4: keep BOTH checks — they answer different questions. `nowEstablished` is whether the job
    // survives the next login; `nowRunning` is whether it is enforcing anything this session.
    BOOL nowEstablished = [self blinkeredInstallLegacyLaunchAgent];
    BOOL nowRunning = [self blinkeredAgentRunningWithin:5.0];
    DDLogInfo(@"Blinkered: LaunchAgent (re)install complete — established=%d running=%d", nowEstablished, nowRunning);
    // Repair report: the device was paired and the agent had genuinely gone missing, and we just
    // brought it back. Fire once (server dedupes) so a silently-unlockable stretch is visible. The
    // case where the agent was ALIVE and we failed to re-establish it is reported inside the install
    // itself (C8) — this gate cannot see it.
    if (reportRepair && !wasRunning && nowRunning) {
        [self blinkeredReportAgentRepaired];
    }
}

// Polls `launchctl list` for our agent label, every 0.5s up to `timeout`
// seconds. Returns YES as soon as it appears, NO if it never does.
// Synchronous on purpose — blinkeredInstallLaunchAgent is called from the
// savepair URL handler which quits the app right after, and we need the
// verification done before that quit.
- (BOOL)blinkeredAgentLoadedWithin:(NSTimeInterval)timeout {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while ([deadline timeIntervalSinceNow] > 0) {
        NSTask *task = [NSTask new];
        task.launchPath = @"/bin/launchctl";
        task.arguments = @[@"list"];
        NSPipe *pipe = [NSPipe pipe];
        task.standardOutput = pipe;
        task.standardError = [NSPipe pipe];   // discard
        @try {
            [task launch]; [task waitUntilExit];
            NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
            NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if ([output containsString:@"app.blinkered.agent"]) return YES;
        } @catch (__unused NSException *e) {}
        [NSThread sleepForTimeInterval:0.5];
    }
    return NO;
}

// Per-user agent log path (see blinkeredInstallLegacyLaunchAgent for why this must NOT be /tmp).
- (NSString *)blinkeredAgentLogPath {
    NSString *logsDir = [[NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES) firstObject]
        stringByAppendingPathComponent:@"Logs"];
    return [logsDir stringByAppendingPathComponent:@"blinkered-agent.log"];
}

// YES only if the agent is actually RUNNING (has a live PID) — not merely registered. A crashing
// agent stays registered with launchd (PID '-', last exit status set) yet enforces nothing; the old
// "is it loaded?" check wrongly treated that as healthy and so never repaired it.
- (BOOL)blinkeredAgentRunningWithin:(NSTimeInterval)timeout {
    NSString *agentBinary = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Contents/MacOS/BlinkeredAgent"];
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    do {
        // Fail-to-NO is correct HERE (wasRunning): an unanswerable probe repairs unnecessarily,
        // which costs a restart. C13 must NOT inherit that default — see blinkeredAgentProcessLiveness:.
        if ([self blinkeredAgentProcessLiveness:agentBinary] == BlinkeredAgentLivenessAlive) { return YES; }
        if ([deadline timeIntervalSinceNow] > 0) { [NSThread sleepForTimeInterval:0.5]; }
    } while ([deadline timeIntervalSinceNow] > 0);
    return NO;
}

// C12 — observe the AGENT PROCESS, not the job's PID.
//
// Before C11 these were the same proposition: the job's program WAS the agent, so `launchctl list`
// showing a PID meant the agent was alive. The wrapper severs that, and every consumer of this method
// inherited the error — the no-op's `wasRunning` term, the agent_repaired gate, and C8's last-resort
// direct launch, which would decline to fire because a SPINNING wrapper holds the PID and then report
// agent_repaired for a device that is not lockable at all. The report would say the opposite of the
// truth.
//
// `ps -axo pid=,comm=` and an EXACT match on this bundle's agent path. Measured: after `exec`, a
// compiled binary's `comm` is its full path (no truncation at these lengths); a wrapper that is still
// spinning because the binary is missing has `comm` = /bin/zsh and correctly does not match. Matching
// the command LINE instead would be wrong — the wrapper's command line contains the agent path, which
// is precisely the false positive this exists to remove.
- (BlinkeredAgentLiveness)blinkeredAgentProcessLiveness:(NSString *)agentBinary {
    NSString *out = nil;
    // C12a — UID-SCOPED. `ps -axo pid=,comm=` lists OTHER USERS' processes too, and their comm is a
    // full path (measured: 198 of 204 non-owned rows on a developer Mac). On a family Mac with two
    // accounts logged in — fast user switching, which runbook §4 tells the tester to do — both run the
    // agent from the same /Applications/…/BlinkeredAgent, so account A's probe matches account B's
    // agent. That is C12's own headline misreport still reachable: agent_repaired dispatched for a
    // device that is not lockable at all.
    //
    // This was a REGRESSION the C12 fix introduced: `launchctl list` was scoped to the caller's own
    // gui/<uid> domain and could not see another user's job. C12 removed one false positive (the
    // wrapper) and installed another in the same method.
    //
    // H3 — and it goes through the BOUNDED runner, so a wedged ps cannot hang the launch path.
    int status = [self blinkeredRunTool:@"/bin/ps" args:@[@"-axo", @"uid=,pid=,comm="] output:&out];
    if (status != 0 || out.length == 0) {
        DDLogError(@"Blinkered: agent liveness UNKNOWN — ps returned %d (%@)", status, out);
        return BlinkeredAgentLivenessUnknown;
    }
    NSString *myUid = [NSString stringWithFormat:@"%u", getuid()];
    for (NSString *line in [out componentsSeparatedByString:@"\n"]) {
        // Fields are uid, pid, comm — and comm is the REST OF THE LINE, not the third
        // whitespace-separated token: a bundle path may contain spaces (/Users/…/Rory's Mac).
        // Splitting on whitespace would silently never match such a path.
        NSString *rest = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSRange sp = [rest rangeOfString:@" "];
        if (sp.location == NSNotFound) { continue; }
        NSString *uid = [rest substringToIndex:sp.location];
        rest = [[rest substringFromIndex:sp.location + 1]
                stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        sp = [rest rangeOfString:@" "];
        if (sp.location == NSNotFound) { continue; }
        NSString *comm = [rest substringFromIndex:sp.location + 1];
        if (![uid isEqualToString:myUid]) { continue; }   // C12a: this user's agent only
        if ([comm isEqualToString:agentBinary]) { return BlinkeredAgentLivenessAlive; }
    }
    return BlinkeredAgentLivenessDead;
}



// YES if the installed plist already logs to the current per-user path — so an old plist still
// pointing at the shared /tmp log is treated as needs-repair and every Mac migrates on next launch.
// C11 migration. YES only if the installed plist already reaches the agent through the out-of-bundle
// launcher. Every device in the fleet has a plist whose ProgramArguments[0] is the bundle binary, so
// this is false on all of them and the repair rewrites the plist on the next launch.
//
// Independent of liveness and of establishment — it reads the file — so unlike the C7 term this one
// cannot be implied by the others. A bundle-resident job can be running AND established AND still be
// about to vanish at the next login; that is exactly what was measured.
// F6 — is a locked session live RIGHT NOW?
//
// Both terms are FILES, and that is the whole point. C10's per-launch latch is process-local, and the
// repair CREATES processes: it restarts the agent, the restarted agent cold-launches the live lock,
// and Blinkered comes back as a NEW process with the latch cleared. A flag cannot bound an event that
// resets the flag. These two survive a relaunch because they are on disk.
//
// `last-lock.json` is the agent's own cached lock — written when a lock starts, cleared on unlock, and
// what the agent re-asserts from offline. It is live for exactly as long as the lock is, including
// across an agent or app restart. That also makes its coverage match the hazard: the damage here comes
// from a restarted agent finding a lock to cold-launch, and a lock it can cold-launch is one this file
// records. `home_session.json` adds the app-owned home-lock identity.
- (BOOL)blinkeredLockSessionLive {
    NSString *support = [[NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject]
        stringByAppendingPathComponent:@"Blinkered"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:
         [support stringByAppendingPathComponent:@"last-lock.json"]]) { return YES; }
    return [self blinkeredHomeSessionInfo] != nil;
}

- (BOOL)blinkeredPlistIsCanonical:(NSString *)plistPath {
    NSString *agentBinary = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Contents/MacOS/BlinkeredAgent"];
    NSDictionary *installed = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    if (![installed isKindOfClass:[NSDictionary class]]) { return NO; }
    // C11b + G5 — the WHOLE plist, against THIS bundle. Not args[0]; not ProgramArguments alone; and
    // not a hardcoded element count, which would have been wrong the moment C11a added `-f`.
    // Comparing to the canonical dictionary validates the launcher, the -f flag, the script text,
    // argv0, the agent path, RunAtLoad, KeepAlive, the label and both log paths in one statement —
    // and it stays correct when any of their shapes change again.
    return [installed isEqualToDictionary:
            [self blinkeredAgentPlistFor:agentBinary logPath:[self blinkeredAgentLogPath]]];
}



- (BOOL)blinkeredPlistUsesCurrentLogPath:(NSString *)plistPath {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    return [plist isKindOfClass:[NSDictionary class]] &&
           [plist[@"StandardOutPath"] isKindOfClass:[NSString class]] &&
           [plist[@"StandardOutPath"] isEqualToString:[self blinkeredAgentLogPath]];
}

// Writes the plist and registers the agent in the per-user GUI domain. Returns YES only when the
// job is VERIFIED present in gui/<uid> afterwards — never on an unread or assumed outcome.
- (BOOL)blinkeredInstallLegacyLaunchAgent {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *agentBinary = [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Contents/MacOS/BlinkeredAgent"];

    // ── THERE IS DELIBERATELY NO SMAppService UNREGISTER HERE. Do not add one back. ────────────────
    //
    // This function used to open by calling `[SMAppService agentServiceWithPlistName:
    // @"app.blinkered.agent.plist"] unregisterAndReturnError:nil]` whenever `.status` read Enabled.
    // That call is what took a family Mac off the air, and it had shipped since 3.6.53 (21 Jun 2026).
    //
    // WHY IT FIRED. The bundle ships Contents/Library/LaunchAgents/app.blinkered.agent.plist whose
    // Label is app.blinkered.agent — the SAME label as the legacy ~/Library/LaunchAgents job this
    // function installs. Measured with a Developer-ID probe on our own team: a same-Label legacy job
    // makes `.status` read Enabled with NO SMAppService registration in existence. So the guard was
    // true on every healthy device and the call ran against our own live agent.
    //
    // WHAT IT DID. Returned error 144 ("lacks required entitlement") AND DISABLED THE ITEM ANYWAY —
    // job booted out, agent killed, and a Background Task Management `disabled` disposition that
    // survives reboots and reinstalls, is invisible to `launchctl print-disabled`, and makes launchd
    // skip the item at EVERY subsequent login. The function then wrote the plist and bootstrapped,
    // which succeeds on a disabled item, so the session looked healthy and the device went dark at the
    // next login — permanently, because the repair lives in an app a dark device never launches.
    //
    // GUARDING IT IS NOT ENOUGH. A first fix gated the call on our legacy plist being absent; a review
    // falsified that. With the plist DELETED but the job still loaded, `.status` still reads
    // enabled(1) and the unregister still flips the BTM record — a child reaches that state with one
    // `rm` in their own home directory. Plist presence is a CORRELATED discriminator, not a causal one.
    //
    // WHY DELETING IS SAFE. The block's purpose was to stop the SMAppService and legacy mechanisms both
    // running ("double agent = double-launched locks"). That cannot happen: both use the SAME Label,
    // launchd holds one service per label per domain, and the code below boots out whatever holds
    // `gui/<uid>/app.blinkered.agent` before bootstrapping ours. A stale SMAppService registration is
    // displaced by that bootout; it cannot run alongside us.
    //
    // So the correct number of SMAppService calls in this function is ZERO, and
    // tools/lockdown-tests/check-agent-no-self-unregister.sh pins exactly that.

    // FAIL CLOSED on an underivable Library path. `firstObject` on an empty array is nil, and
    // -stringByAppendingPathComponent: on nil yields nil, so every path below would be built on nothing.
    NSArray *libraryDirs = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    NSString *userLibrary = [libraryDirs firstObject];
    if (userLibrary.length == 0) {
        DDLogError(@"Blinkered: cannot derive the user Library directory — refusing to install the "
                   @"LaunchAgent against a nil path.");
        return NO;
    }
    NSString *launchAgentDir = [userLibrary stringByAppendingPathComponent:@"LaunchAgents"];
    [fm createDirectoryAtPath:launchAgentDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *plistPath = [launchAgentDir stringByAppendingPathComponent:@"app.blinkered.agent.plist"];

    // Per-user log path — NOT a shared /tmp file. /tmp/blinkered-agent.log is owned by whichever
    // account's agent created it first; on a multi-account (family) Mac launchd then CANNOT open it
    // for the OTHER accounts, so it kills the agent before main() with exit 78 and — because the log
    // is the very thing it can't open — writes nothing. That silently broke locking on standard kid
    // accounts (diagnosed July 2026). ~/Library/Logs is always owned by the running user.
    NSString *logPath = [self blinkeredAgentLogPath];
    [fm createDirectoryAtPath:[logPath stringByDeletingLastPathComponent]
  withIntermediateDirectories:YES attributes:nil error:nil];

    // C11 — THE PROGRAM MUST NOT LIVE INSIDE THE APP BUNDLE. This is the condition that actually
    // makes the agent come back, and it is not obvious; do not "simplify" it back to @[agentBinary].
    //
    // Measured on Maggie's Mac, 21 Aug 2026 (uid 503, one boot throughout). A job that was PROVEN
    // established — `submitted job` marker absent, `domain = gui/503`, verified before the logout —
    // did not survive the fleet's real logout/login cycle: agent gone, `print` exit 113. Meanwhile
    // com.blinkered.shieldloop, in the SAME directory, same user, same login, came back every time.
    // The only difference between the two jobs was ProgramArguments[0]: /bin/zsh vs a path inside
    // /Applications/Blinkered.app. launchd logs nothing at login — it establishes one and silently
    // skips the other.
    //
    // Rewriting THIS job's ProgramArguments to the launcher form below, with a prediction recorded in
    // advance and nothing else touched, made it survive the identical cycle: fresh "Started" line at
    // the login timestamp, new pid, parent PID 1 = launchd, `print` exit 0.
    //
    // `exec` replaces the shell with the agent, so no wrapper process is left behind and pgrep still
    // finds .../MacOS/BlinkeredAgent.
    //
    // THE SPIN GUARD is the loop, and it is load-bearing. With KeepAlive, a shell that exits
    // immediately because the binary is missing gets relaunched forever — and the binary IS briefly
    // missing every time Sparkle replaces the bundle. shieldloop does not have this problem because
    // it loops internally; this must do the same. So: wait, rather than exit and let launchd retry.
    // A sleeping shell costs nothing, and the agent returns by itself the moment the bundle is back.
    // C11/C11a/C11b/G5 — built in ONE place and compared against in ONE place, so the installer and
    // the migration check cannot drift apart about what a correct plist looks like.
    NSDictionary *plist = [self blinkeredAgentPlistFor:agentBinary logPath:logPath];

    // F5 — BRANCH ON THE WRITE. An unwritable plist silently left the OLD file in place while the
    // rest of this method reported on the new intent — and with the bootout below, that is how a pass
    // leaves a device worse off than it found it. Same defect class as the unread launchctl status.
    if (![plist writeToFile:plistPath atomically:YES]) {
        DDLogError(@"Blinkered: FAILED to write the LaunchAgent plist at %@ — declining to boot out a "
                   @"working agent to install something that is not there.", plistPath);
        return NO;
    }

    NSString *domain = [self blinkeredGUIDomainTarget];
    NSString *service = [self blinkeredAgentServiceTarget];

    // C1 — DOMAIN-TARGETED, and ESTABLISHING rather than submitting. `launchctl load`/`unload` submit
    // the job: launchd flags it "submitted job" and does not re-create it from the service directory
    // when the domain is rebuilt at login. Confirmed on Poppy's Mac by a prediction made in advance —
    // `print` exit 0 with the marker before the logout, exit 113 after.
    //
    // C2/C3 — READ AND BRANCH ON EVERY STATUS, and capture stderr. Doubly the point here, because the
    // legacy subcommands cannot be checked at all: `launchctl load` prints "Load failed: 5: Input/
    // output error" on stderr and STILL EXITS 0 (measured). Reading load's status would have told us
    // nothing. bootstrap/bootout return honest statuses — an independent reason to use them.
    NSString *bootoutOut = nil;
    int bootoutStatus = [self blinkeredRunLaunchctl:@[@"bootout", service] output:&bootoutOut];
    if (bootoutStatus == 0) {
        DDLogInfo(@"Blinkered: booted the previous agent out of %@", domain);
    } else if (bootoutStatus == kBlinkeredLaunchctlNoSuchProcess) {
        DDLogInfo(@"Blinkered: no agent in %@ to boot out (ESRCH) — first install or already out", domain);
    } else {
        DDLogWarn(@"Blinkered: bootout of %@ failed with status %d (%@) — bootstrapping anyway",
                  service, bootoutStatus, bootoutOut);
    }

    // C8 — bootout+bootstrap is NOT atomic, and we have just booted out an agent that may have been
    // perfectly healthy. If bootstrap fails now, the device is agentless for the rest of the session:
    // no locks, no watchdog, no offline re-lock, nobody told. That is §3.4's catastrophe, newly
    // reachable on a device that was fine before this pass. So: retry, and never return without
    // having tried to leave SOMETHING running.
    int bootstrapStatus = 0;
    NSString *bootstrapOut = nil;
    BlinkeredAgentEstablishment established = BlinkeredAgentEstablishmentUnknown;
    const int kAttempts = 3;
    for (int attempt = 1; attempt <= kAttempts; attempt++) {
        bootstrapStatus = [self blinkeredRunLaunchctl:@[@"bootstrap", domain, plistPath] output:&bootstrapOut];
        // C4 — the STATUS is never the verdict. `bootstrap` returns 5 for "already bootstrapped", for
        // a missing plist, and as its generic error, so it is not trusted in either direction. The
        // establishment probe decides, and it is what every branch below is gated on.
        established = [self blinkeredAgentEstablishment];
        if (established == BlinkeredAgentEstablishmentEstablished) { break; }
        DDLogWarn(@"Blinkered: bootstrap attempt %d/%d into %@ did not establish the agent "
                  @"(status %d, establishment %ld) — %@",
                  attempt, kAttempts, domain, bootstrapStatus, (long)established, bootstrapOut);
        if (attempt < kAttempts) { [NSThread sleepForTimeInterval:0.5]; }
    }

    // F5 — the success line must ALSO require that what is ON DISK is the launcher form. A job can
    // establish from a plist we did not write; claiming "installed and ESTABLISHED" would then be
    // asserting something about a different file. Re-read it rather than trust the write.
    BOOL launcherOnDisk = [self blinkeredPlistIsCanonical:plistPath];
    if (established == BlinkeredAgentEstablishmentEstablished && launcherOnDisk) {
        // C3 — the ONLY place this line may be written, and it says what actually happened. The old
        // code logged "installed and started" unconditionally, so a device in the broken state wrote
        // a log line claiming it was fine. That is the condition that would have surfaced this bug on
        // day one.
        DDLogInfo(@"Blinkered: LaunchAgent installed and ESTABLISHED in %@ from %@ (bootstrap status %d, "
                  @"launcher verified on disk)", domain, plistPath, bootstrapStatus);
        return YES;
    }

    DDLogError(@"Blinkered: LaunchAgent did NOT establish in %@ after %d attempts — this device will "
               @"NOT be lockable after the next login. plist=%@ bootstrap status=%d establishment=%ld "
               @"launcherOnDisk=%d output=%@",
               domain, kAttempts, plistPath, bootstrapStatus, (long)established, launcherOnDisk, bootstrapOut);

    // C8 fallback: getting the device through THIS session matters more than getting it through the
    // next login. If nothing is running, start the agent binary directly. It is a degraded agent — no
    // KeepAlive, gone at logout — but a device with a degraded agent can still be locked, and one with
    // no agent cannot be locked at all. Only when nothing is live: spawning alongside a running agent
    // is the double-agent hazard C6 exists to prevent.
    if (![self blinkeredAgentRunningWithin:0.1]) {
        DDLogError(@"Blinkered: no agent is running — starting %@ directly as a last resort", agentBinary);
        NSTask *direct = [NSTask new];
        direct.launchPath = agentBinary;
        @try { [direct launch]; } @catch (NSException *e) {
            DDLogError(@"Blinkered: direct agent launch threw: %@", e.reason);
        }
    }
    BOOL liveAfterFallback = [self blinkeredAgentRunningWithin:5.0];

    // C8 — and TELL SOMEONE. blinkeredReportAgentRepaired cannot fire for this: its caller gates on
    // (!wasRunning && nowRunning), which is false in the case that matters — an agent that WAS healthy,
    // that we booted out, and that we then failed to re-establish.
    // Two explicit calls, not a ternary: the security-event contract gate extracts literal types with
    // `blinkeredReportSecurityEvent:@"..."`, and a ternary hides both from it — which is exactly the
    // silently-reduced-coverage shape that gate exists to catch. It caught this one.
    if (liveAfterFallback) {
        [self blinkeredReportSecurityEvent:@"agent_repaired"];
    } else {
        [self blinkeredReportSecurityEvent:@"agent_install_failed"];
    }
    DDLogError(@"Blinkered: agent install fell back — running=%d, established=NO. The device is %@.",
               liveAfterFallback,
               liveAfterFallback ? @"lockable this session but not after the next login"
                                 : @"NOT LOCKABLE AT ALL");
    return NO;
}

- (void)applicationDidFinishLaunchingProceed
{
    if (!_isReconfiguringToMDMConfig) {
        if (_openingSettings && _openingSettingsFileURL) {
            DDLogDebug(@"%s Open file: %@", __FUNCTION__, _openingSettingsFileURL);
            [self openFile:_openingSettingsFileURL];
            _openingSettingsFileURL = nil;
        } else {
            [self didFinishLaunchingWithSettings];
        }
    }
    // Blinkered: a session launch never hits the bare-launch update check, so kick off a
    // silent background check now. With SUAutomaticallyUpdate the new version downloads
    // during the session and installs on quit — so even a brief locked session pulls the
    // update (the hourly scheduled check alone is too slow to catch short sessions).
    if (!_blinkeredSessionUpdateScheduled) {
        _blinkeredSessionUpdateScheduled = YES;
        [self performSelector:@selector(blinkeredBackgroundUpdateCheck) withObject:nil afterDelay:5.0];
    }
}

static BOOL _blinkeredSessionUpdateScheduled = NO;

- (void)blinkeredBackgroundUpdateCheck {
    @try {
        if (self.updaterController.updater) {
            DDLogInfo(@"Blinkered: session launch — silent background update check");
            [self.updaterController.updater checkForUpdatesInBackground];
        }
    } @catch (NSException *e) {
        DDLogError(@"Blinkered: background update check failed: %@", e.reason);
    }
}


#pragma mark - Open configuration file

- (void)openFile:(NSURL *)sebFileURL
{
    DDLogDebug(@"%s Open file: %@", __FUNCTION__, sebFileURL.absoluteString);
    
    DDLogInfo(@"Open file event: Loading .seb settings file with URL %@", sebFileURL);
    
    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    
    _alternateKeyPressed = [self alternateKeyCheck];
    
    // Check if preferences window is open
    if (self.settingsOpen) {
        
        /// Open settings file in preferences window for editing
        
        [self.preferencesController openSEBPrefsAtURL:sebFileURL];
        
    } else {

        /// Open settings file for exam/reconfiguring client

        // Blinkered: a .seb opened here (not in the prefs editor) is a SESSION — most importantly the
        // parent-lock home session the agent launches via `open /tmp/blinkered-home-session.seb`,
        // which macOS delivers to application:openFile: → here, NOT application:openURLs:. It was
        // launched while the kid's student.html tab is open, so on exit return to THAT tab — don't
        // let applicationWillTerminateProceed open a fresh student.html tab (the recurring
        // "lock → unlock spawns a duplicate tab" regression). This is the file-open counterpart of
        // the same flag we set in application:openURLs: for the blinkered://join + .seb-URL paths.
        _blinkeredSkipTerminateReturn = YES;

        // Check if any alerts are open in SEB, abort opening if yes
        if (_modalAlertWindows.count > 0) {
            DDLogError(@"%lu Modal window(s) displayed, aborting before opening new settings.", (unsigned long)_modalAlertWindows.count);
        }
        
        // Check if SEB is in an exam session and reconfiguring isn't allowed
        if (!_startingUp && ![self.browserController isReconfiguringAllowedFromURL:sebFileURL]) {
            _openingSettings = NO;
            return;
        }
        
        if (_alternateKeyPressed) {
            DDLogInfo(@"Option/alt key being held while SEB is started, will open Preferences window.");
            if (self.aboutWindow.isVisible) {
                DDLogDebug(@"%s About SEB window is visible, attempting to close it.", __FUNCTION__);
                [self closeAboutWindow];
            }
            [self.preferencesController openSEBPrefsAtURL:sebFileURL];
        }
        
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_downloadAndOpenSebConfig"]) {
            NSError *error = nil;
            NSData *sebData = [NSData dataWithContentsOfURL:sebFileURL options:NSDataReadingUncached error:&error];
            
            if (!error) {
                // Save the path to the file for possible editing in the preferences window
                [[MyGlobals sharedMyGlobals] setCurrentConfigURL:sebFileURL];
                
                // Decrypt and store the .seb config file
                [self.configFileController storeNewSEBSettings:sebData
                                                    forEditing:NO
                                                      callback:self
                                                      selector:@selector(storeNewSEBSettingsSuccessful:)];
                return;
            } else {
                //ToDo: Show alert for file loading error
            }
        } else {
            [self.browserController showAlertNotAllowedDownloadingAndOpeningSebConfig:YES];
        }
    }
    _openingSettings = NO;
}


- (void)storeNewSEBSettings:(NSData *)sebData
                 forEditing:(BOOL)forEditing
     forceConfiguringClient:(BOOL)forceConfiguringClient
      showReconfiguredAlert:(BOOL)showReconfiguredAlert
                   callback:(id)callback
                   selector:(SEL)selector
{
    DDLogDebug(@"%s forEditing: %d forceConfiguringClient: %d showReconfiguredAlert: %d callback: %@ selector: %@", __FUNCTION__, forEditing, forceConfiguringClient, showReconfiguredAlert, callback, NSStringFromSelector(selector));
    [self.configFileController storeNewSEBSettings:sebData
                                     forEditing:forEditing
                         forceConfiguringClient:forceConfiguringClient
                          showReconfiguredAlert:showReconfiguredAlert
                                       callback:callback
                                       selector:selector];
}


- (void) storeNewSEBSettingsSuccessful:(NSError *)error
{
    DDLogDebug(@"%s, error: %@", __FUNCTION__, error);
    
    if (!error) {
        // If successfull start/restart with new settings
        _openingSettings = NO;
        
        [self updateAACAvailablility];
        
        if (!_startingUp) {
            // SEB is being reconfigured by opening a config file
            [self requestedRestart];
        } else {
            [self didFinishLaunchingWithSettings];
        }
        
    } else {
        NSAlert *modalAlert = [self newAlert];
        [modalAlert setMessageText:[error.userInfo objectForKey:NSLocalizedDescriptionKey]];
        [modalAlert setInformativeText:[error.userInfo objectForKey:NSLocalizedFailureReasonErrorKey]];
        [modalAlert addButtonWithTitle:(!_establishingSEBServerConnection && !_startingUp) ? NSLocalizedString(@"OK", @"") : (!self.quittingSession ? [NSString stringWithFormat:NSLocalizedString(@"Quit %@", @""), SEBFullAppNameClassic] : NSLocalizedString(@"Quit Session", @""))];
        [modalAlert setAlertStyle:NSAlertStyleCritical];
        void (^storeNewSEBSettingsNotSuccessfulHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self removeAlertWindow:modalAlert.window];
            if (self.startingUp) {
                // we quit, as decrypting the config wasn't successful
                DDLogError(@"SEB was started with a SEB Config File as argument, but decrypting this configuration failed: Terminating.");
                [self requestedExit:nil]; // Quit SEB
            } else if (self.establishingSEBServerConnection) {
                [self sessionQuitRestart:NO];
            }
        };
        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))storeNewSEBSettingsNotSuccessfulHandler];
        _openingSettings = NO;
    }
}


#pragma mark - Methods called after starting up by opening settings successfully

- (void)didOpenSettings
{
    DDLogDebug(@"%s", __FUNCTION__);
    _openingSettings = NO;
    [self updateAACAvailablility];

    if (_startingUp) {
        // If SEB was just started (by opening a config file)
        [self didFinishLaunchingWithSettings];
        
    } else {
        // SEB is being reconfigured by opening a config file
        [self requestedRestart];
    }
}


- (void)didFinishLaunchingWithSettings
{
    DDLogDebug(@"%s", __FUNCTION__);
    _runningProhibitedProcesses = [NSMutableArray new];
    _terminatedProcessesExecutableURLs = [NSMutableSet new];

    _alternateKeyPressed = [self alternateKeyCheck];

    if (_alternateKeyPressed) {
        DDLogInfo(@"Option/alt key being held while SEB is started, will open Preferences window.");
        if (self.aboutWindow.isVisible) {
            DDLogDebug(@"%s About SEB window is visible, attempting to close it.", __FUNCTION__);
            [self closeAboutWindow];
        }
        [self saveCurrentPasteboardString];
        [self openPreferences:self];

    } else {
        [self updateAACAvailablility];
        DDLogInfo(@"isAACEnabled = %hhd", _isAACEnabled);

        // Reset SEB Browser
        [self.browserController resetBrowser];

        if (!_openingSettings) {
            // Initialize SEB according to client settings
            [self conditionallyInitSEBWithCallback:self
                                          selector:@selector(didFinishLaunchingWithSettingsProcessesChecked)];
        } else if (_isAACEnabled == NO) {
            // Cover all attached screens with cap windows to prevent clicks on desktop making finder active
            [self coverScreens];
        }
    }
}

- (void)didFinishLaunchingWithSettingsProcessesChecked
{
    if (_isAACEnabled == NO) {
        // Check for command key being held down
        [self appSwitcherCheck];
        
        // Cover all attached screens with cap windows to prevent clicks on desktop making finder active
        [self coverScreens];

        // Block screen shots
//        if ([NSUserDefaults standardUserDefaults].blockScreenShotsLegacy) {
//            [self killScreenCaptureAgent];
//        }
        [self.systemManager preventScreenCapture];
    }
    // Start system monitoring and prevent to start SEB if specific
    // system features are activated
    
    [self startSystemMonitoring];
    
    // Set up SEB Browser
    
    self.browserController.reinforceKioskModeRequested = YES;
    
    // [§3.4/§5 step 3] Drop the other session type's quit credentials BEFORE the browser opens, so
    // no window and no interceptor can observe a stale one. Owns the cleanup the removed
    // /seb-setquit interceptor used to do, and the one a skipped start-URL write would miss.
    [self blinkeredClearStaleSessionCredentials];

    // Open the main browser window
    DDLogDebug(@"%s openMainBrowserWindow", __FUNCTION__);

    [self startExamWithFallback:NO];

    // [§8.9] A home lock whose start-URL write never happened is invisible to both the quit path
    // and the watchdog. Turn that into a reported signal rather than a silent degraded session.
    [self blinkeredScheduleHomeSessionSanityCheck];

    // SEB finished starting up, reset the flag for starting up
    _startingUp = false;

    [self performSelector:@selector(performAfterStartActions:) withObject: nil afterDelay: 2];
    
    if (_openingSettings && _openingSettingsFileURL) {
        DDLogDebug(@"%s Open file: %@", __FUNCTION__, _openingSettingsFileURL);
        [self performSelector:@selector(openFile:) withObject: _openingSettingsFileURL.copy afterDelay: 2.5];
        _openingSettingsFileURL = nil;
    }

}


- (void) startExamWithFallback:(BOOL)fallback
{
    DDLogInfo(@"%s", __FUNCTION__);
    if (_establishingSEBServerConnection == YES && !fallback) {
        [AccessibilityFeaturesManager controlVoiceOver];
        _startingExamFromSEBServer = YES;
        [self.serverController startExamFromServer];
    } else {
        if (self.sebServerConnectionEstablished && [[NSUserDefaults standardUserDefaults] secureIntegerForKey:@"org_safeexambrowser_SEB_sebMode"] == sebModeSebServer) {
            // Stop/Reset proctoring
            [self stopProctoringWithCompletion:^{
                DDLogDebug(@"%s Conditionally closed (optional) proctoring", __FUNCTION__);
                    DDLogInfo(@"%s: There is already a SEB Server session running and the new session is also a SEB Server session: Terminate the running SEB Server session before starting the new one.", __FUNCTION__);
                    [self conditionallyCloseSEBServerConnectionWithRestart:NO completion:^(BOOL restart) {
                        self.establishingSEBServerConnection = NO;
                        DDLogDebug(@"%s Conditionally closed (optional) SEB Server connection (restart: %d)", __FUNCTION__, restart);
                        run_on_ui_thread(^{
                            [self startExamAccessibilityCheckWithFallback:fallback];
                        });
                    }];
            }];
            
        } else {
            [self startExamAccessibilityCheckWithFallback:fallback];
        }
    }
}


- (void) startExamAccessibilityCheckWithFallback:(BOOL)fallback
{
    DDLogInfo(@"%s", __FUNCTION__);
    [AccessibilityFeaturesManager controlVoiceOver];

    [self startExamFromSEBServerWithFallback:fallback];
}


- (void) startExamFromSEBServerWithFallback:(BOOL)fallback
{
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_sebMode"] == sebModeSebServer &&
            !fallback) {
            NSString *sebServerURLString = [preferences secureStringForKey:@"org_safeexambrowser_SEB_sebServerURL"];
            NSDictionary *sebServerConfiguration = [preferences secureDictionaryForKey:@"org_safeexambrowser_SEB_sebServerConfiguration"];
            _establishingSEBServerConnection = YES;
            NSError *error = [self.serverController connectToServer:[NSURL URLWithString:sebServerURLString] withConfiguration:sebServerConfiguration];
            if (!error) {
                // All necessary information for connecting to SEB Server was available in settings:
                // try to connect to SEB Server and wait for delegate method to be called with success/failure
                [self showSEBServerView];
                return;
            } else {
                // Cannot connect as some SEB Server settings/API endpoints are missing
                [self didFailWithError:error fatal:YES];
                return;
            }
        }
        // ToDo: Implement Initial Configuration Assistant
        //        NSString *startURLString = [[NSUserDefaults standardUserDefaults] secureStringForKey:@"org_safeexambrowser_SEB_startURL"];
        //        NSURL *startURL = [NSURL URLWithString:startURLString];
        //        if (startURLString.length == 0 ||
        //            (([startURL.host hasSuffix:@"safeexambrowser.org"] ||
        //              [startURL.host hasSuffix:SEBWebsiteShort]) &&
        //             [startURL.path hasSuffix:@"start"]))
        //        {
        //            // Start URL was set to the default value, show init assistant
        //            [self openInitAssistant];
        //        } else {
                    _sessionRunning = true;
                    
                    // Load all open web pages from the persistent store and re-create webview(s) for them
                    // or if no persisted web pages are available, load the start URL
                    [self.browserController openMainBrowserWindow];
                    
        // Persist start URL of a "secure" exam
        [self persistSecureExamStartURL:self.sessionState.startURL.absoluteString configKey:self.configKey];
        //        }

}

// Persist start URL of a secure exam
- (void) persistSecureExamStartURL:(NSString *)startURLString configKey:(NSData *)configKey
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if (preferences.secureSession) {
        currentExamStartURL = startURLString;
        currentExamConfigKey = configKey;
        [self.sebLockedViewController addLockedExam:currentExamStartURL configKey: currentExamConfigKey];
    } else {
        currentExamStartURL = nil;
        currentExamConfigKey = nil;
    }
    self.isReconfiguringToMDMConfig = NO;
}

#pragma mark - Connecting to SEB Server

- (void) showSEBServerView
{
    _sebServerViewController = [SEBServerOSXViewController new];
    _sebServerViewController.sebServerController = self.serverController.sebServerController;
    self.serverController.sebServerController.serverControllerUIDelegate = _sebServerViewController;
    _sebServerViewController.serverControllerDelegate = self;
    NSWindow *sebServerViewWindow;
    sebServerViewWindow = [NSWindow windowWithContentViewController:_sebServerViewController];
    if (_sessionState.allowSwitchToApplications) {
        [sebServerViewWindow setLevel:NSModalPanelWindowLevel-1];
    } else {
        [sebServerViewWindow setLevel:NSMainMenuWindowLevel+5];
    }
    sebServerViewWindow.title = NSLocalizedString(@"Connecting to SEB Server", @"");
    sebServerViewWindow.delegate = _sebServerViewController;
    NSWindowController *sebServerViewWindowController = [[NSWindowController alloc] initWithWindow:sebServerViewWindow];
    _sebServerViewWindowController = sebServerViewWindowController;
    [_sebServerViewWindowController showWindow:nil];

    _sebServerViewDisplayed = YES;
    [_sebServerViewController updateExamList];
}

- (void) closeServerView
{
    _sebServerViewWindowController.window.delegate = nil;
    [_sebServerViewWindowController close];
    _sebServerViewController = nil;
    _sebServerViewDisplayed = NO;
}


- (void) startBatteryMonitoringWithDelegate:(id)delegate
{
    [self.batteryController addDelegate:delegate];
    [self.batteryController startMonitoringBattery];
}


- (void) didSelectExamWithExamId:(NSString *)examId url:(NSString *)url
{
    [self.serverController examSelected:examId url:url];
}


- (void) storeNewSEBSettingsFromData:(NSData *)configData
{
    [self storeNewSEBSettings:configData forEditing:NO forceConfiguringClient:NO showReconfiguredAlert:NO callback:self selector:@selector(storeNewSEBSettingsSuccessful:)];
}


- (NSString * _Nullable)appSignatureKey {
    return [self.browserController.appSignatureKey base16String];
}


- (void)didReceiveExamSalt:(NSString * _Nonnull)examSalt connectionToken:(NSString * _Nonnull)connectionToken{
    if (examSalt.length > 0) {
        self.browserController.examSalt = [NSData dataWithBase16String:examSalt];
        self.browserController.connectionToken = connectionToken;
    } else {
        self.browserController.examSalt = nil;
        self.browserController.connectionToken = nil;
    }
}


- (void)didReceiveServerBEK:(NSString * _Nonnull)serverBEK {
    if (serverBEK.length > 0) {
        self.browserController.serverBrowserExamKey = [NSData dataWithBase16String:serverBEK];
    } else {
        self.browserController.serverBrowserExamKey = nil;
    }
}


- (void) loginToExam:(NSString *)url
{
    NSURL *examURL = [NSURL URLWithString:url];
    self.sessionState.sebServerExamStartURL = examURL;
    DDLogDebug(@"Session state: sebServerExamURL = %@", self.sessionState.sebServerExamStartURL);
    [self.browserController openMainBrowserWindowWithStartURL:examURL];
    [self persistSecureExamStartURL:url configKey:self.configKey];
    _sessionRunning = YES;
}


- (void) didEstablishSEBServerConnection
{
    _establishingSEBServerConnection = NO;
    _startingExamFromSEBServer = NO;
    _sebServerConnectionEstablished = YES;
}


- (void) didFailWithError:(NSError *)error fatal:(BOOL)fatal
{
    BOOL optionallyAttemptFallback = fatal && !_startingExamFromSEBServer && !_sebServerConnectionEstablished;
    DDLogError(@"SEB Server connection did fail with error: %@%@", [error.userInfo objectForKey:NSDebugDescriptionErrorKey], optionallyAttemptFallback ? @", optionally attempt failback" : @" This is a non-fatal error, no fallback necessary.");
    NSString *localizedRecoverySuggestion = [error.userInfo objectForKey:NSLocalizedRecoverySuggestionErrorKey];
    if (localizedRecoverySuggestion.length == 0) {
        localizedRecoverySuggestion = NSLocalizedString(@"Contact your exam administrator", comment: "");
    }
    NSString *informativeText = [NSString stringWithFormat:@"%@\n%@", [error.userInfo objectForKey:NSLocalizedDescriptionKey], localizedRecoverySuggestion];
    if (optionallyAttemptFallback) {
        if (!self.serverController.fallbackEnabled) {
            DDLogError(@"Aborting SEB Server connection as fallback isn't enabled");
            [self closeServerViewWithCompletion:^{
                NSAlert *modalAlert = [self newAlert];
                [modalAlert setMessageText:NSLocalizedString(@"Connection to SEB Server Failed", @"")];
                [modalAlert setInformativeText:informativeText];
                [modalAlert addButtonWithTitle:!self.quittingSession ? [NSString stringWithFormat:NSLocalizedString(@"Quit %@", @""), SEBFullAppNameClassic] : NSLocalizedString(@"Quit Session", @"")];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"Retry", @"")];
                [modalAlert setAlertStyle:NSAlertStyleCritical];
                void (^closeServerViewHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                    [self removeAlertWindow:modalAlert.window];
                    switch(answer)
                    {
                        case NSAlertFirstButtonReturn:
                        {
                            [self closeServerViewAndRestart:self];
                            break;
                        }
                        default:
                            DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld. Retrying to connect to SEB Server.", (long)answer);
                        case NSAlertSecondButtonReturn:
                        {
                            self.establishingSEBServerConnection = NO;
                            [self startExamWithFallback:NO];
                            break;
                        }
                    }
                };
                [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))closeServerViewHandler];
            }];
            return;;
        } else {
            [self closeServerViewWithCompletion:^{
                DDLogInfo(@"Server connection failed: Querying user if fallback should be used");
                NSAlert *modalAlert = [self newAlert];
                [modalAlert setMessageText:NSLocalizedString(@"Connection to SEB Server Failed: Fallback Option", @"")];
                [modalAlert setInformativeText:informativeText];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"Retry", @"")];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"Fallback", @"")];
                [modalAlert addButtonWithTitle:!self.quittingSession ? [NSString stringWithFormat:NSLocalizedString(@"Quit %@", @""), SEBFullAppNameClassic] : NSLocalizedString(@"Quit Session", @"")];
                [modalAlert setAlertStyle:NSAlertStyleCritical];
                void (^closeServerViewHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                    [self removeAlertWindow:modalAlert.window];
                    switch(answer)
                    {
                        default:
                            DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld. Retrying to connect to SEB Server.", (long)answer);
                        case NSAlertFirstButtonReturn:
                        {
                            DDLogInfo(@"User selected Retry option");
                            self.establishingSEBServerConnection = NO;
                            [self startExamWithFallback:NO];
                            break;
                        }
                        case NSAlertSecondButtonReturn:
                        {
                            DDLogInfo(@"User selected Fallback option");
                            NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
                            NSString *sebServerFallbackPasswordHash = [preferences secureStringForKey:@"org_safeexambrowser_SEB_sebServerFallbackPasswordHash"];
                            // If SEB Server fallback password is set, then restrict fallback
                            if (sebServerFallbackPasswordHash.length != 0) {
                                DDLogInfo(@"%s Displaying SEB Server fallback password alert", __FUNCTION__);
                                [self showEnterPasswordDialog:NSLocalizedString(@"Enter SEB Server fallback password:", @"") modalForWindow:self.browserController.mainBrowserWindow pseudoModal:NO windowTitle:@""];
                                NSString *password = [self.enterPassword stringValue];
                                
                                SEBKeychainManager *keychainManager = [[SEBKeychainManager alloc] init];
                                if (password.length > 0 && [sebServerFallbackPasswordHash caseInsensitiveCompare:[keychainManager generateSHAHashString:password]] == NSOrderedSame) {
                                    DDLogInfo(@"Correct SEB Server fallback password entered");
                                    DDLogInfo(@"Open startURL as SEB Server fallback");
                                    self.establishingSEBServerConnection = NO;
                                    [self startExamWithFallback:YES];

                                } else {
                                    DDLogInfo(@"%@ SEB Server fallback password entered", password.length > 0 ? @"Wrong" : @"No");
                                    NSAlert *modalAlert = [self newAlert];
                                    [modalAlert setMessageText:password.length > 0 ? NSLocalizedString(@"Wrong SEB Server Fallback Password entered", @"") : NSLocalizedString(@"No SEB Server Fallback Password entered", @"")];
                                    [modalAlert setInformativeText:NSLocalizedString(@"If you don't enter the correct SEB Server fallback password, then you cannot invoke fallback.", @"")];
                                    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                                    [modalAlert setAlertStyle:NSAlertStyleWarning];
                                    void (^wrongPasswordEnteredOK)(NSModalResponse) = ^void (NSModalResponse answer) {
                                        [self removeAlertWindow:modalAlert.window];
                                        [self didFailWithError:error fatal:fatal];
                                    };
                                    [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))wrongPasswordEnteredOK];
                                }
                            } else {
                                DDLogInfo(@"Open startURL as SEB Server fallback");
                                self.establishingSEBServerConnection = NO;
                                [self startExamWithFallback:YES];
                            }
                            break;
                        }
                        case NSAlertThirdButtonReturn:
                        {
                            DDLogInfo(@"User selected Quit option");
                            [self closeServerViewAndRestart:self];
                            break;
                        }
                    }
                };
                [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))closeServerViewHandler];
            }];
            return;
        }
    }
}


- (void) closeServerViewAndRestart:(id)sender
{
    [self closeServerViewWithCompletion:^{
        [self sessionQuitRestart:NO];
    }];
}


- (void) closeServerViewWithCompletion:(void (^)(void))completion
{
    [self closeServerView];
    completion();
}


- (void) serverSessionQuitRestart:(BOOL)restart
{
    DDLogDebug(@"%s", __FUNCTION__);
    
    self.establishingSEBServerConnection = NO;
    if (_sebServerViewDisplayed) {
        [self closeServerView];
    }
    // Check if Preferences are currently open
    if (self.settingsOpen) {
        // Close Preferences
        [self closePreferencesWindow];
    }
    [self sessionQuitRestart:restart];
}


- (void) didCloseSEBServerConnectionRestart:(BOOL)restart
{
    _establishingSEBServerConnection = NO;
    if (restart) {
        [self requestedRestart];
    } else {
        [self quitSEBOrSession];
    }
}


- (void) examineCookies:(NSArray<NSHTTPCookie *>*)cookies forURL:(NSURL *)url
{
    if (_establishingSEBServerConnection) {
        [self.serverController examineCookies:cookies forURL:url];
    }
}


- (void) examineHeaders:(NSDictionary<NSString *,NSString *>*)headerFields forURL:(NSURL *)url
{
    [self.serverController examineHeaders:headerFields forURL:url];
}


- (void) shouldStartLoadFormSubmittedURL:(NSURL *)url
{
    if (_establishingSEBServerConnection) {
        [self.serverController shouldStartLoadFormSubmittedURL:url];
    }
}


#pragma mark - Remote Proctoring

- (void) openZoomView
{
    DDLogDebug(@"%s", __FUNCTION__);
    
    if (@available(iOS 11.0, *)) {
        self.previousSessionZoomEnabled = YES;
        
        // Initialize Zoom settings
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        _zoomReceiveAudio = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_zoomReceiveAudio"];
        _zoomReceiveVideo = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_zoomReceiveVideo"];
        _zoomSendAudio = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_zoomSendAudio"];
        _zoomSendVideo = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_zoomSendVideo"];
        _remoteProctoringViewShowPolicy = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_remoteProctoringViewShow"];
    }
}

- (void) proctoringInstructionWithAttributes:(NSDictionary *)attributes
{
    DDLogDebug(@"%s", __FUNCTION__);
    
    NSString *serviceType = attributes[@"service-type"];
    DDLogInfo(@"%s: Service type: %@", __FUNCTION__, serviceType);
    
    if ([serviceType isEqualToString:proctoringServiceTypeScreenProctoring]) {
        NSString *instructionConfirm = attributes[@"instruction-confirm"];
        if (![instructionConfirm isEqualToString:self.serverController.sebServerController.pingInstruction]) {
            self.serverController.sebServerController.pingInstruction = instructionConfirm;
            if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_enableScreenProctoring"]) {
                [self.screenProctoringController proctoringInstructionWithAttributes:attributes];
            } else {
                DDLogError(@"%s: Received Screen Proctoring JOIN instruction, despite screen proctoring not being enabled in SEB Settings, ignoring it!", __FUNCTION__);
            }
        }
    } else {
        DDLogError(@"%s: Cannot execute proctoring instruction, unknown Service Type in attributes %@!", __FUNCTION__, attributes);
    }
}

- (void) reconfigureWithAttributes:(NSDictionary *)attributes
{
    DDLogDebug(@"%s: attributes: %@", __FUNCTION__, attributes);
}

- (void) lockSEBWithAttributes:(NSDictionary *)attributes
{
    DDLogDebug(@"%s: attributes: %@", __FUNCTION__, attributes);
    NSString *message = attributes[@"message"];
    [[NSNotificationCenter defaultCenter]
     postNotificationName:@"lockSEB" object:self userInfo:@{@"lockReason" : message ? message : [NSString stringWithFormat:NSLocalizedString(@"%@ was locked by SEB Server. Please contact your exam support.", @""), SEBShortAppName]}];
}

- (void) confirmNotificationWithAttributes:(NSDictionary *)attributes
{
    DDLogDebug(@"%s: attributes: %@", __FUNCTION__, attributes);
    NSString *notificationType = attributes[@"type"];
    NSNumber *notificationIDNumber = [attributes objectForKey:@"id"];
    
    if ([notificationType isEqualToString:@"raisehand"]) {
        if (_raiseHandRaised && raiseHandUID == notificationIDNumber.integerValue) {
            [self toggleRaiseHandLoweredByServer:YES];
        }
    }
    
    if ([notificationType isEqualToString:@"lockscreen"]) {
        if (self.sebServerPendingLockscreenEvents.count > 0) {
#ifdef DEBUG
        DDLogDebug(@"sebServerPendingLockscreenEvents: %@", self.sebServerPendingLockscreenEvents);
#endif
            NSInteger notificationID = notificationIDNumber.integerValue;
            for (NSUInteger index = 0 ; index < self.sebServerPendingLockscreenEvents.count ; ++index) {
                if (self.sebServerPendingLockscreenEvents[index].integerValue == notificationID) {
                    [self.sebServerPendingLockscreenEvents removeObjectAtIndex:index];
                }
            }
    #ifdef DEBUG
            DDLogDebug(@"sebServerPendingLockscreenEvents after removing notificationID %@: %@", notificationIDNumber, self.sebServerPendingLockscreenEvents);
    #endif
            if (self.sebServerPendingLockscreenEvents.count == 0) {
                DDLogInfo(@"No pending lock screen events, closing lockdown windows invoked by SEB Server");
                [self closeLockdownWindowsAllowOverride:NO];
            }
        }
    }
}


- (void) stopProctoringWithCompletion:(void (^)(void))completionHandler
{
    if (_screenProctoringController) {
        [_screenProctoringController closeSessionWithCompletionHandler:^{
            self->_screenProctoringController = nil;
            completionHandler();
        }];
        return;
    }
    completionHandler();
}


- (void) proctoringFailedWithErrorMessage:(NSString *)errorMessage
{
    [[NSNotificationCenter defaultCenter]
     postNotificationName:@"proctoringFailed" object:self userInfo:@{NSLocalizedFailureReasonErrorKey : errorMessage}];
}


- (void) toggleProctoringViewVisibility
{
    DDLogDebug(@"%s", __FUNCTION__);
}


- (void) setProctoringViewButtonState:(remoteProctoringButtonStates)remoteProctoringButtonState
{
    [self setProctoringViewButtonState:remoteProctoringButtonState userFeedback:YES];
}


- (void) setProctoringViewButtonState:(remoteProctoringButtonStates)remoteProctoringButtonState
                         userFeedback:(BOOL)userFeedback
{
    NSImage *remoteProctoringButtonImage;
    NSColor *remoteProctoringButtonTintColor;
    switch (remoteProctoringButtonState) {
        case remoteProctoringButtonStateNormal:
//            remoteProctoringButtonImage = ProctoringIconNormalState;
            remoteProctoringButtonTintColor = ProctoringIconColorNormalState;
//            _sebViewController.proctoringStateIcon = ProctoringBadgeNormalState;
            break;
            
        case remoteProctoringButtonStateWarning:
//            remoteProctoringButtonImage = ProctoringIconWarningState;
            remoteProctoringButtonTintColor = ProctoringIconColorWarningState;
//            _sebViewController.proctoringStateIcon = ProctoringBadgeWarningState;
            break;
            
        case remoteProctoringButtonStateError:
//            remoteProctoringButtonImage = ProctoringIconErrorState;
            remoteProctoringButtonTintColor = ProctoringIconColorErrorState;
//            _sebViewController.proctoringStateIcon = ProctoringBadgeErrorState;
            break;
            
        case remoteProctoringButtonStateAIInactive:
            if (@available(macOS 10.14, *)) {
                _dockButtonProctoringView.image.template = YES;
                remoteProctoringButtonTintColor = ProctoringIconColorNormalState;
            } else {
                remoteProctoringButtonImage = ProctoringIconAIInactiveState;
            }
//            _sebViewController.proctoringStateIcon = nil;
            break;
            
        default:
            if (@available(macOS 10.14, *)) {
                remoteProctoringButtonImage.template = NO;
                remoteProctoringButtonTintColor = nil;
            } else {
                remoteProctoringButtonImage = ProctoringIconDefaultState;
            }
//            _sebViewController.proctoringStateIcon = nil;
            break;
    }
    if (userFeedback) {
        if (@available(macOS 10.14, *)) {
            _dockButtonProctoringView.contentTintColor = remoteProctoringButtonTintColor;
        } else {
            _dockButtonProctoringView.image = remoteProctoringButtonImage;
        }
    }
}


#pragma mark - Raise Hand Feature

- (void) toggleRaiseHand
{
    [self toggleRaiseHandLoweredByServer:NO];
}

- (void) toggleRaiseHandLoweredByServer:(BOOL)loweredByServer
{
    DDLogInfo(@"%s", __FUNCTION__);
    
    if (_raiseHandRaised) {
        _raiseHandRaised = NO;
        _dockButtonRaiseHand.image = RaisedHandIconDefaultState;
        if (@available(macOS 10.14, *)) {
            _dockButtonRaiseHand.contentTintColor = RaisedHandIconColorDefaultState;
        }
        if (!loweredByServer) {
            [self.serverController sendLowerHandNotificationWithUID:raiseHandUID];
        }
        
    } else {
        if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_raiseHandButtonAlwaysPromptMessage"]) {
            [self showEnterRaiseHandMessageWindow];
        } else {
            [self raiseHand];
        }
    }
}

- (void) raiseHand
{
    if (!_raiseHandRaised) {
        _raiseHandRaised = YES;
        _dockButtonRaiseHand.image = RaisedHandIconRaisedState;
        if (@available(macOS 10.14, *)) {
            _dockButtonRaiseHand.contentTintColor = RaisedHandIconColorRaisedState;
        }
        raiseHandUID = [self.serverController sendRaiseHandNotificationWithMessage:raiseHandNotification];
        raiseHandNotification = @"";
    }
}


- (void) showEnterRaiseHandMessageWindow
{
    if (!_raiseHandRaised) {
        NSWindow *windowToShowModalFor;

        if (@available(macOS 12.0, *)) {
        } else {
            if (@available(macOS 11.0, *)) {
                if (_isAACEnabled || _wasAACEnabled) {
                    windowToShowModalFor = self.browserController.mainBrowserWindow;
                }
            }
        }

        [NSApp beginSheet: _enterRaiseHandMessageWindow
           modalForWindow: windowToShowModalFor
            modalDelegate: nil
           didEndSelector: nil
              contextInfo: nil];
        [NSApp runModalForWindow: _enterRaiseHandMessageWindow];
        // Dialog is up here.
        [NSApp endSheet: _enterRaiseHandMessageWindow];
        self.raiseHandMessageTextField.stringValue = @"";
        [_enterRaiseHandMessageWindow orderOut: self];
        [self removeAlertWindow:_enterRaiseHandMessageWindow];
        if (raiseHandNotification) {
            [self raiseHand];
        }
    }
}


- (IBAction)sendEnteredRaiseHandMessage:(id)sender
{
    raiseHandNotification = self.raiseHandMessageTextField.stringValue;
    [NSApp stopModal];
}

- (IBAction)cancelEnteringRaiseHandMessage:(id)sender
{
    raiseHandNotification = nil;
    [NSApp stopModal];
}


#pragma mark - Screen Proctoring Delegate Methods

- (NSDictionary<NSString *,NSString *>*) getScreenProctoringMetadataActiveAppWindow
{
    NSString *activeBrowserWindowTitle; // = self.browserController.activeBrowserWindowTitle;

    // Get the process ID of the frontmost application.
    NSRunningApplication* app = [[NSWorkspace sharedWorkspace]
                                 frontmostApplication];
    pid_t pid = [app processIdentifier];
    
    // See if we have accessibility permissions, and if not, prompt the user to
    // visit System Preferences.
    NSDictionary *options = @{(id)CFBridgingRelease(kAXTrustedCheckOptionPrompt): @YES};
    Boolean appHasPermission = AXIsProcessTrustedWithOptions(
                                                             (__bridge CFDictionaryRef)options);
    if (!appHasPermission) {
        // we don't have accessibility permissions
        DDLogError(@"SEB is not trusted in Privacy / Accessibility, cannot read title of frontmost windows!");
    } else {
        // Get the accessibility element corresponding to the frontmost application.
        AXUIElementRef appElem = AXUIElementCreateApplication(pid);
        if (!appElem) {
            return nil;
        }
        
        // Get the accessibility element corresponding to the frontmost window
        // of the frontmost application.
        AXUIElementRef window = NULL;
        if (AXUIElementCopyAttributeValue(appElem,
                                          kAXFocusedWindowAttribute, (CFTypeRef*)&window) != kAXErrorSuccess) {
            CFRelease(appElem);
            return nil;
        } else {
            // Finally, get the title of the frontmost window.
            CFStringRef title = NULL;
            AXError result = AXUIElementCopyAttributeValue(window, kAXTitleAttribute,
                                                           (CFTypeRef*)&title);
            
            // At this point, we don't need window and appElem anymore.
            CFRelease(window);
            CFRelease(appElem);
            
            if (result == kAXErrorSuccess) {
                activeBrowserWindowTitle = CFBridgingRelease(title);
            }
        }
    }

    NSString *activeAppInfo = [NSString stringWithFormat:@"%@ (Bundle ID: %@, Path: %@)", app.localizedName, app.bundleIdentifier, app.bundleURL.path];
    
    if (activeBrowserWindowTitle == nil) {
        activeBrowserWindowTitle = @"";
    }
    
    if (sebPID == pid) {
        activeBrowserWindowTitle = [self.browserController windowTitleByRemovingSEBVersionString:activeBrowserWindowTitle];
    }
    
    NSDictionary *activeAppWindowMetadata = @{@"activeApp": activeAppInfo, @"activeWindow": activeBrowserWindowTitle};
    return activeAppWindowMetadata;
}


- (NSString *) getScreenProctoringMetadataURL
{
    return self.browserController.activeBrowserWindow.currentURL.absoluteString;
}

- (NSString *) getScreenProctoringMetadataBrowser
{
    return self.browserController.openWebpagesTitlesString;
}


#pragma mark - Screen Proctoring SPSControllerUIDelegate methods

- (void) updateStatusWithString:(NSString *)string append:(BOOL)append
{
    run_on_ui_thread(^{
        self.dockButtonScreenProctoring.toolTip = string;
    });
}


- (void) screenProctoringButtonAction
{
    DDLogDebug(@"%s", __FUNCTION__);
}


- (void) setScreenProctoringButtonState:(ScreenProctoringButtonStates)screenProctoringButtonState
{
    [self setScreenProctoringButtonState:screenProctoringButtonState userFeedback:YES];
}

- (void) setScreenProctoringButtonState:(ScreenProctoringButtonStates)screenProctoringButtonState
                           userFeedback:(BOOL)userFeedback
{
    run_on_ui_thread(^{
        NSImage *screenProctoringButtonImage;
        NSColor *screenProctoringButtonTintColor;
        DDLogDebug(@"[SEBController setScreenProctoringButtonState: %ld userFeedback: %@]", (long)screenProctoringButtonState, userFeedback ? @"YES" : @"NO");
        switch (screenProctoringButtonState) {
            case ScreenProctoringButtonStateActive:
                self.dockButtonScreenProctoringStateString = NSLocalizedString(@"Screen Proctoring Active",nil);
                self.dockButtonScreenProctoring.toolTip = self.dockButtonScreenProctoringStateString;
                screenProctoringButtonImage = self->ScreenProctoringIconActiveState;
                screenProctoringButtonTintColor = self->ScreenProctoringIconColorActiveState;
                break;
                
            case ScreenProctoringButtonStateActiveWarning:
                screenProctoringButtonImage = self->ScreenProctoringIconActiveWarningState;
                screenProctoringButtonTintColor = self->ScreenProctoringIconColorWarningState;
                break;
                
            case ScreenProctoringButtonStateActiveError:
                screenProctoringButtonImage = self->ScreenProctoringIconActiveErrorState;
                screenProctoringButtonTintColor = self->ScreenProctoringIconColorErrorState;
                break;
                
            case ScreenProctoringButtonStateInactive:
            default:
                self.dockButtonScreenProctoringStateString = NSLocalizedString(@"Screen Proctoring Inactive",nil);
                self.dockButtonScreenProctoring.toolTip = self.dockButtonScreenProctoringStateString;
                screenProctoringButtonImage = self->ScreenProctoringIconInactiveState;
                break;
        }
        if (userFeedback) {
            screenProctoringButtonImage.template = YES;
            self.dockButtonScreenProctoring.image = screenProctoringButtonImage;
            if (@available(macOS 10.14, *)) {
                self.dockButtonScreenProctoring.contentTintColor = screenProctoringButtonTintColor;
            }
        }
    });
}


- (void) setScreenProctoringButtonInfoString:(NSString *)infoString
{
    run_on_ui_thread(^{
        if (infoString.length == 0) {
            self.dockButtonScreenProctoring.toolTip = self.dockButtonScreenProctoringStateString;
        } else {
            self.dockButtonScreenProctoring.toolTip = [NSString stringWithFormat:@"%@ (%@)", self.dockButtonScreenProctoringStateString, infoString];
        }
    });
}


- (void)showTransmittingCachedScreenShotsWindowWithRemainingScreenShots:(NSInteger)remainingScreenShots message:(NSString * _Nullable)message operation:(NSString * _Nullable)operation
{
    run_on_ui_thread(^{
        if (self->_transmittingCachedScreenShotsViewController) {
            [self updateTransmittingCachedScreenShotsWindowWithRemainingScreenShots:self.latestNumberOfCachedScreenShotsWhileClosing message:nil operation:nil totalScreenShots:remainingScreenShots];
        } else {
            self.lockModalWindows = [self fillScreensWithCoveringWindows:coveringWindowModalAlert
                                                            windowLevel:NSScreenSaverWindowLevel
                                                         excludeMenuBar:false];

            NSWindow *transmittingCachedScreenShotsWindow;
            transmittingCachedScreenShotsWindow = [NSWindow windowWithContentViewController:self.transmittingCachedScreenShotsViewController];
            self.transmittingCachedScreenShotsViewController.progressBar.minValue = 0;
            self.transmittingCachedScreenShotsViewController.progressBar.maxValue = remainingScreenShots;
            self.transmittingCachedScreenShotsViewController.progressBar.doubleValue = remainingScreenShots;
            self.latestNumberOfCachedScreenShotsWhileClosing = remainingScreenShots;
            if (message) {
                self.transmittingCachedScreenShotsViewController.message.stringValue = message;
            }
            if (operation) {
                self.transmittingCachedScreenShotsViewController.operations.stringValue = operation;
            }

            [transmittingCachedScreenShotsWindow setLevel:NSScreenSaverWindowLevel+1];
            transmittingCachedScreenShotsWindow.styleMask  &= ~(NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable);
            transmittingCachedScreenShotsWindow.title = NSLocalizedString(@"Finalizing Screen Proctoring", @"");
            NSWindowController *windowController = [[NSWindowController alloc] initWithWindow:transmittingCachedScreenShotsWindow];
            self.transmittingCachedScreenShotsWindowController = windowController;
            [self.transmittingCachedScreenShotsWindowController showWindow:nil];
        }
    });
}


- (void)updateTransmittingCachedScreenShotsWindowWithRemainingScreenShots:(NSInteger)remainingScreenShots message:(NSString * _Nullable)message operation:(NSString * _Nullable)operation totalScreenShots:(NSInteger)totalScreenShots
{
    [self updateTransmittingCachedScreenShotsWindowWithRemainingScreenShots:remainingScreenShots message:message operation:operation append:NO totalScreenShots:totalScreenShots];
}

- (void)updateTransmittingCachedScreenShotsWindowWithRemainingScreenShots:(NSInteger)remainingScreenShots message:(NSString * _Nullable)message operation:(NSString * _Nullable)operation append:(BOOL)append totalScreenShots:(NSInteger)totalScreenShots
{
    self.latestNumberOfCachedScreenShotsWhileClosing = remainingScreenShots;
    run_on_ui_thread(^{
        if (self->_transmittingCachedScreenShotsViewController) {
            self.transmittingCachedScreenShotsViewController.progressBar.doubleValue = remainingScreenShots;
            self.transmittingCachedScreenShotsViewController.progressBar.maxValue = totalScreenShots;
            if (message) {
                self.transmittingCachedScreenShotsViewController.message.stringValue = message;
            }
            if (operation) {
                NSString *updatedOperations = operation;
                if (append && self.operationsString.length > 0) {
                    NSString *separator = [self.operationsString hasSuffix:@"."] ? @"" : @".";
                    updatedOperations = [NSString stringWithFormat:@"%@%@ %@", self.operationsString, separator, operation];
                }
                self.transmittingCachedScreenShotsViewController.operations.stringValue = updatedOperations;
                self.operationsString = updatedOperations;
            }
        }
    });
}


- (void)allowQuit:(BOOL)allowQuit
{
    run_on_ui_thread(^{
        if (self->_transmittingCachedScreenShotsViewController) {
            self.transmittingCachedScreenShotsViewController.quitButton.hidden = !allowQuit;
        }
    });
}

- (void)closeTransmittingCachedScreenShotsWindow:(void (^ _Nonnull)(void))completion
{
    run_on_ui_thread(^{
        self.transmittingCachedScreenShotsViewController.uiDelegate = nil;
        [self.transmittingCachedScreenShotsWindowController close];
        self.transmittingCachedScreenShotsViewController = nil;
        [self closeLockModalWindows];
        completion();
    });
}


#pragma mark - Initialization depending on client or opened settings

- (void) conditionallyInitSEBWithCallback:(id)callback
                                 selector:(SEL)selector;
{
    if (_openingSettings) {
        DDLogDebug(@"OpeningSettings = true, abort %s", __FUNCTION__);
        return;
    }
    DDLogDebug(@"%s", __FUNCTION__);
    
    /// Kiosk mode checks
    
    // Check if running on minimal macOS version
    [self checkMinMacOSVersion];
    
    // Check if launched SEB is placed ("installed") in an Applications folder
    [self installedInApplicationsFolder];
    
    
    // Check if any prohibited processes are running and terminate them
    
    [[ProcessManager sharedProcessManager] updateMonitoredProcesses];
    
    NSArray *prohibitedApplications = [ProcessManager sharedProcessManager].prohibitedApplications;
    NSArray *prohibitedBSDProcesses = [ProcessManager sharedProcessManager].prohibitedBSDProcesses;
    
    [self terminateApplications:prohibitedApplications processes:prohibitedBSDProcesses starting:YES restarting:NO callback:callback selector:selector];
}


- (void) terminateApplications:(NSArray *)prohibitedApplications
                     processes:(NSArray *)prohibitedBSDProcesses
                      starting:(BOOL)starting
                    restarting:(BOOL)restarting
                      callback:(id)callback
                      selector:(SEL)selector
{
    DDLogDebug(@"%s starting: %d restarting: %d callback: %@ selector: %@", __FUNCTION__, starting, restarting, callback, NSStringFromSelector(selector));
   // Get all running processes, including daemons
    NSArray *allRunningProcesses = [self getProcessArray];
    self.runningProcesses = allRunningProcesses;
    
    NSMutableArray <NSRunningApplication *>*runningApplications = [NSMutableArray new];
    NSMutableArray <NSDictionary *>*runningProcesses = [NSMutableArray new];
    
    NSArray *permittedApplications = [ProcessManager sharedProcessManager].permittedApplications;
    if (permittedApplications && permittedApplications.count > 0) {
        DDLogInfo(@"There are permitted additional applications (which will be added to the list of apps to be quit before %@ the exam session): %@", starting ? @"starting" : @"ending", permittedApplications);
        prohibitedApplications = [prohibitedApplications arrayByAddingObjectsFromArray:permittedApplications];
    }
    BOOL autoQuitApplications = [[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_autoQuitApplications"];
    
    // Check if any prohibited processes are running
    for (NSDictionary *process in allRunningProcesses) {
        NSNumber *PID = process[@"PID"];
        pid_t processPID = PID.intValue;
        NSRunningApplication *runningApplication = [NSRunningApplication runningApplicationWithProcessIdentifier:processPID];
        NSString *bundleID = runningApplication.bundleIdentifier;
        if (bundleID) {
            // NSRunningApplication
            NSPredicate *processFilter = [NSPredicate predicateWithFormat:@"%@ LIKE self", bundleID];
            NSArray *matchingProhibitedApplications = [prohibitedApplications filteredArrayUsingPredicate:processFilter];
            if (matchingProhibitedApplications.count != 0) {
                DDLogInfo(@"This %@ application is running and has to be quit first before %@ the exam session: %@", starting ? @"not allowed" : @"permitted", starting ? @"starting" : @"ending", matchingProhibitedApplications);
                NSURL *appURL = [self getBundleOrExecutableURL:runningApplication];
                if (appURL && starting) {
                    // Add the app's file URL, so we can restart it when exiting SEB
                    [_terminatedProcessesExecutableURLs addObject:appURL];
                }
                NSDictionary *prohibitedProcess = [[ProcessManager sharedProcessManager] prohibitedProcessWithIdentifier:bundleID];
                if ([prohibitedProcess[@"strongKill"] boolValue] == YES) {
                    DDLogInfo(@"Settings allow to force terminate this running application: %@", runningApplication);
                    if (![runningApplication kill]) {
                        [runningApplications addObject:runningApplication];
                    }
                } else {
                    [runningApplications addObject:runningApplication];
                    if (autoQuitApplications) {
                        [runningApplication terminate];
                    }
                }
            }
        } else {
            // BSD process
            NSPredicate *processNameFilter = [NSPredicate predicateWithFormat:@"%@ LIKE self", process[@"name"]];
            NSArray *filteredProcesses = [prohibitedBSDProcesses filteredArrayUsingPredicate:processNameFilter];
            if (filteredProcesses.count != 0) {
                NSDictionary *prohibitedProcess = [[ProcessManager sharedProcessManager] prohibitedProcessWithExecutable:process[@"name"]];
                DDLogInfo(@"This not allowed process is running and has to terminated before %@ the exam session: %@", starting ? @"starting" : @"ending", prohibitedProcess);
                if ([prohibitedProcess[@"strongKill"] boolValue] == YES) {
                    if (![NSRunningApplication killProcessWithPID:processPID error:nil]) {
                        [runningProcesses addObject:process];
                    } else {
                        NSString *executablePath = [ProcessManager getExecutablePathForPID:processPID];
                        if (executablePath) {
                            NSURL *processURL = [NSURL fileURLWithPath:executablePath isDirectory:NO];
                            // Add the process' file URL, so we can restart it when exiting SEB
                            [_terminatedProcessesExecutableURLs addObject:processURL];
                        }
                    }
                } else {
                    [runningProcesses addObject:process];
                }
            }
        }
    }
    
    // Continue immediately when nothing is left terminating. The fixed 1s grace
    // below exists to give surviving processes time to die before prompting the
    // user — but it also ran when every kill had already succeeded synchronously
    // (or nothing prohibited was running at all), adding a flat second to every
    // session start and end.
    if (runningApplications.count + runningProcesses.count == 0) {
        [self conditionallyContinueAfterTerminatingAppsWithCallback:callback restarting:restarting selector:selector starting:starting];
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        // Check if all prohibited processes did terminate and otherwise prompt the user
        if (runningApplications.count + runningProcesses.count > 0) {
            self.processListViewController.runningApplications = runningApplications;
            self.processListViewController.runningProcesses = runningProcesses;
            self.processListViewController.callback = callback;
            self.processListViewController.selector = selector;
            self.processListViewController.starting = starting;
            self.processListViewController.restarting = restarting;
            
            [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
            
            NSWindow *runningProcessesListWindow;
            runningProcessesListWindow = [NSWindow windowWithContentViewController:self.processListViewController];
            [runningProcessesListWindow setLevel:NSMainMenuWindowLevel+5];
            runningProcessesListWindow.title = NSLocalizedString(@"Prohibited Processes Are Running", @"");
            NSWindowController *processListWindowController = [[NSWindowController alloc] initWithWindow:runningProcessesListWindow];
            self.runningProcessesListWindowController = processListWindowController;
            // Check if the process wasn't closed in the meantime (race condition)
            // important: processListViewController must be accessed with the instance variable
            // _processListViewController here and not using the property self.processListViewController
            // as otherwise a new instance of the controller will be allocated
            if (self->_processListViewController &&
                self->_processListViewController.runningApplications.count +
                self->_processListViewController.runningProcesses.count > 0) {
                runningProcessesListWindow.delegate = self.processListViewController;
                [self.runningProcessesListWindowController showWindow:nil];
                return;
            }
        } else {
            [self conditionallyContinueAfterTerminatingAppsWithCallback:callback restarting:restarting selector:selector starting:starting];
        }
    });
}


- (void) conditionallyContinueAfterTerminatingAppsWithCallback:(id)callback restarting:(BOOL)restarting selector:(SEL)selector starting:(BOOL)starting
{
    DDLogDebug(@"%s callback: %@ restarting: %d selector: %@ starting: %d", __FUNCTION__, callback, restarting, NSStringFromSelector(selector), starting);
    if (starting) {
        [self conditionallyInitSEBProcessesCheckedWithCallback:callback selector:selector];
    } else {
        if (callback == nil) {
            [self sessionQuitRestartContinue:restarting];
        } else {
            DDLogDebug(@"%s, continue with callback: %@ selector: %@", __FUNCTION__, callback, NSStringFromSelector(selector));
            IMP imp = [callback methodForSelector:selector];
            void (*func)(id, SEL) = (void *)imp;
            func(callback, selector);
        }
    }
}


- (NSMutableArray *)checkProcessesRunning:(NSMutableArray *)runningProcesses
{
    // Get all running processes, including daemons
    NSArray *allRunningProcesses = [self getProcessArray];
    self.runningProcesses = allRunningProcesses;
    
    NSUInteger i=0;
    while (i < (runningProcesses).count) {
        NSDictionary *runningProcess = (runningProcesses)[i];
        if (![allRunningProcesses containsObject:runningProcess]) {
            DDLogDebug(@"Running process %@ did terminate", runningProcess[@"name"]);
            [runningProcesses removeObjectAtIndex:i];
        } else {
            i++;
        }
    }
    return runningProcesses;
}


- (void) conditionallyInitSEBProcessesCheckedWithCallback:(id)callback
                                                 selector:(SEL)selector
{
    if (_openingSettings) {
        DDLogDebug(@"OpeningSettings = true, abort %s", __FUNCTION__);
        return;
    }
    DDLogDebug(@"%s", __FUNCTION__);
    
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if (![preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowVirtualMachine"]) {
        // Check if SEB is running inside a virtual machine
        SInt32        myAttrs;
        OSErr        myErr = noErr;
        
        // Get details for the present operating environment
        // by calling Gestalt (Userland equivalent to CPUID)
        myErr = Gestalt(gestaltX86AdditionalFeatures, &myAttrs);
        if ((myErr == noErr && ((myAttrs & (1UL << 31)) | (myAttrs == 0x209))) || [self.systemManager.systemInfo.sysModelID localizedCaseInsensitiveContainsString:[[NSString alloc] initWithData:[[NSData alloc] initWithBase64EncodedString:@"dklyVFVhTA==" options:NSDataBase64DecodingIgnoreUnknownCharacters] encoding:NSUTF8StringEncoding]] || [self.systemManager.systemInfo.sysModelID localizedCaseInsensitiveContainsString:[[NSString alloc] initWithData:[[NSData alloc] initWithBase64EncodedString:@"dk1XYVJF" options:NSDataBase64DecodingIgnoreUnknownCharacters] encoding:NSUTF8StringEncoding]] || [self.systemManager.systemInfo.sysModelID localizedCaseInsensitiveContainsString:[[NSString alloc] initWithData:[[NSData alloc] initWithBase64EncodedString:@"cUVtVQ==" options:NSDataBase64DecodingIgnoreUnknownCharacters] encoding:NSUTF8StringEncoding]] || [self.systemManager.systemInfo.sysModelID localizedCaseInsensitiveContainsString:[[NSString alloc] initWithData:[[NSData alloc] initWithBase64EncodedString:@"UEFyQWxsRWxT" options:NSDataBase64DecodingIgnoreUnknownCharacters] encoding:NSUTF8StringEncoding]]) {
            // Bit 31 is set: VMware Hypervisor running (?)
            // or gestaltX86AdditionalFeatures values of VirtualBox detected
            DDLogError(@"SERIOUS SECURITY ISSUE DETECTED: SEB was started up in a virtual machine! gestaltX86AdditionalFeatures = %X", myAttrs);
            NSAlert *modalAlert = [self newAlert];
            [modalAlert setMessageText:NSLocalizedString(@"Virtual Machine Detected!", @"")];
            [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"You are not allowed to run %@ inside a virtual machine!", @""), SEBShortAppName]];
            [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
            [modalAlert setAlertStyle:NSAlertStyleCritical];
            void (^vmDetectedHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                [self removeAlertWindow:modalAlert.window];
                [self quitSEBOrSession];
            };
            [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))vmDetectedHandler];
            return;
        } else {
            DDLogInfo(@"SEB is running on a native system (no VM) gestaltX86AdditionalFeatures = %X", myAttrs);
        }
        
        bool    virtualMachine = false;
        // STR or SIDT code?
        virtualMachine = insideMatrix();
        if (virtualMachine) {
            DDLogError(@"SERIOUS SECURITY ISSUE DETECTED: SEB was started up in a virtual machine (Test2)!");
        }
    }
    
    // Check for access control privacy permissions to access log folder
    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_enableLogging"]) {
        NSString *logPath = [preferences secureStringForKey:@"org_safeexambrowser_SEB_logDirectoryOSX"];
        if (logPath.length > 0) {
            logPath = [logPath stringByExpandingTildeInPath];
            NSURL *logDirectory = [NSURL URLWithString:logPath];
            BOOL isLogDirectoryAccessible = [self directoryIsAccessible:logDirectory directoryType:@"log"];
            if (isLogDirectoryAccessible) {
                DDLogInfo(@"Configured log directory %@", logDirectory.path);
            } else {
                DDLogError(@"Can not access configured log directory %@, ask user to grant privacy access permission.", logDirectory.path);
                [[NSWorkspace sharedWorkspace] openURL: [NSURL URLWithString:pathToSecurityPrivacyPreferences]];
                [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];

                NSAlert *modalAlert = [self newAlert];
                [modalAlert setMessageText:NSLocalizedString(@"Grant access to Folder", @"")];
                [modalAlert setInformativeText:[NSString stringWithFormat:@"%@ %@", [NSString stringWithFormat:NSLocalizedString(@"Current settings require access to the directory %@ for saving log files.", @""), logDirectory.path], self.privacyFilesFoldersMessageString]];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"Retry", @"")];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
                [modalAlert setAlertStyle:NSAlertStyleWarning];
                void (^privacyGrantAccessFilesFolderHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                    [self removeAlertWindow:modalAlert.window];
                    switch(answer)
                    {
                        case NSAlertFirstButtonReturn:
                        {
                            [self conditionallyInitSEBProcessesCheckedWithCallback:callback selector:selector];
                            return;
                        }
                            
                        case NSAlertSecondButtonReturn:
                        {
                            [[NSNotificationCenter defaultCenter]
                             postNotificationName:@"requestQuitSEBOrSession" object:self];
                            return;
                        }
                            
                        default:
                            // Can get invoked in case of NSModalResponseStop=-1000 or NSModalResponseAbort=-1001
                        {
                            DDLogError(@"Alert for granting access to log folder was dismissed by the system with NSModalResponse %ld. Retrying", (long)answer);
                            [self conditionallyInitSEBProcessesCheckedWithCallback:callback selector:selector];
                            return;
                        }
                    }
                };
                [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))privacyGrantAccessFilesFolderHandler];
                return;
            }
        }
    }
    
    // Check for access control privacy permissions to access download folders
    
    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDownUploads"] && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDownloads"]) {
        NSURL *downloadDirectory = [self.browserController downloadDirectoryURL];
        BOOL isAccessible = [self directoryIsAccessible:downloadDirectory directoryType:@"download"];
        if (isAccessible) {
            DDLogInfo(@"Configured download directory %@", downloadDirectory.path);
            [self conditionallyInitSEBPermissionsCheckWithCallback:callback selector:selector];
        } else {
            DDLogError(@"Can not access configured download directory %@, ask user to grant privacy access permission.", downloadDirectory.path);
            [[NSWorkspace sharedWorkspace] openURL: [NSURL URLWithString:pathToSecurityPrivacyPreferences]];
            [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];

            NSAlert *modalAlert = [self newAlert];
            [modalAlert setMessageText:NSLocalizedString(@"Grant access to Folder", @"")];
            [modalAlert setInformativeText:[NSString stringWithFormat:@"%@ %@", [NSString stringWithFormat:NSLocalizedString(@"Current settings require access to the directory %@ for saving downloads.", @""), downloadDirectory.path], self.privacyFilesFoldersMessageString]];
            [modalAlert addButtonWithTitle:NSLocalizedString(@"Retry", @"")];
            [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
            [modalAlert setAlertStyle:NSAlertStyleWarning];
            void (^privacyGrantAccessFilesFolderHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                [self removeAlertWindow:modalAlert.window];
                switch(answer)
                {
                    case NSAlertFirstButtonReturn:
                    {
                        [self conditionallyInitSEBProcessesCheckedWithCallback:callback selector:selector];
                        return;
                    }
                        
                    case NSAlertSecondButtonReturn:
                    {
                        [[NSNotificationCenter defaultCenter]
                         postNotificationName:@"requestQuitSEBOrSession" object:self];
                        return;
                    }
                        
                    default:
                        // Can get invoked in case of NSModalResponseStop=-1000 or NSModalResponseAbort=-1001
                    {
                        DDLogError(@"Alert for granting access to download folder was dismissed by the system with NSModalResponse %ld. Retrying", (long)answer);
                        [self conditionallyInitSEBProcessesCheckedWithCallback:callback selector:selector];
                        return;
                    }
                }
            };
            [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))privacyGrantAccessFilesFolderHandler];
            return;
        }
    } else {
        [self conditionallyInitSEBPermissionsCheckWithCallback:callback selector:selector];
    }
}

- (BOOL) directoryIsAccessible:(NSURL *)directoryURL directoryType:(NSString *)directoryType
{
    BOOL isAccessible = NO;
    if (directoryURL) {
        NSFileManager *fileManager= [NSFileManager defaultManager];
        NSError *error;
        NSArray<NSURL *> *downloadDirectoryContents = [fileManager contentsOfDirectoryAtURL:directoryURL includingPropertiesForKeys:nil options:0 error:&error];
        DDLogInfo(@"%@ directory can %@be accessed%@.", [directoryType capitalizedString], downloadDirectoryContents ? @"" : @"not ", error ? [NSString stringWithFormat:@" with error: %@", error] : @"");
        if (error == nil) {
            isAccessible = YES;
        } else {
            DDLogError(@"Accessing %@ directory at %@ failed with error %@.%@", directoryType, directoryURL, error, error.code == 257 ? @" Likely the Privacy access control permissions for this folder are not yet granted or were denied (see System Settings / Privacy & Security / Files & Folders / Safe Exam Browser." : @"");
        }
    }
    return isAccessible;
}




- (void) conditionallyInitSEBPermissionsCheckWithCallback:(id)callback
                                                selector:(SEL)selector
{
    DDLogDebug(@"%s", __FUNCTION__);
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    
    // Check microphone/camera/screen capturing/proctoring permissions
    
    BOOL browserMediaCaptureCamera = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_browserMediaCaptureCamera"];
    BOOL browserMediaCaptureMicrophone = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_browserMediaCaptureMicrophone"];
    BOOL browserMediaCaptureScreen = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_browserMediaCaptureScreen"];
    
    BOOL screenProctoringEnable = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_enableScreenProctoring"];
    BOOL jitsiMeetEnable = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_jitsiMeetEnable"];
    BOOL zoomEnable = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_zoomEnable"];
    BOOL proctoringSession = jitsiMeetEnable || zoomEnable;
    BOOL webApplications = browserMediaCaptureCamera || browserMediaCaptureMicrophone;
    if (jitsiMeetEnable || zoomEnable) {
        browserMediaCaptureCamera = YES;
        browserMediaCaptureMicrophone = YES;
    }
    BOOL isETHExam = [self.sessionState.startURL.host hasSuffix:@"ethz.ch"] ||
    [_serverController.url.host hasSuffix:@"ethz.ch"];
    
    if ((zoomEnable && !ZoomProctoringSupported) || (jitsiMeetEnable && !JitsiMeetProctoringSupported)) {
        NSString *notAvailableRequiredRemoteProctoringService = [NSString stringWithFormat:@"%@%@", zoomEnable && !ZoomProctoringSupported ? @"Zoom " : @"",
                                                                 jitsiMeetEnable && !JitsiMeetProctoringSupported ? @"Jitsi Meet " : @""];
        DDLogError(@"%@Remote proctoring not available", notAvailableRequiredRemoteProctoringService);
        NSAlert *modalAlert = [self newAlert];
        [modalAlert setMessageText:NSLocalizedString(@"Remote Proctoring Not Available", @"")];
        [modalAlert setInformativeText:[NSString stringWithFormat:@"%@%@", [NSString stringWithFormat:NSLocalizedString(@"Current settings require %@remote proctoring, which this %@ version doesn't support. Use the correct %@ version required by your exam organizer.", @""), notAvailableRequiredRemoteProctoringService, SEBShortAppName, SEBShortAppName], zoomEnable == NO ? @"" : [NSString stringWithFormat:@"\n\n%@", NSLocalizedString(@"Due to Zoom licensing issues, Zoom live proctoring is only available for SEB Alliance members. Please see https://safeexambrowser.org/alliance.", @"")]]];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
        [modalAlert setAlertStyle:NSAlertStyleWarning];
        void (^remoteProctoringDisclaimerHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self removeAlertWindow:modalAlert.window];
            [[NSNotificationCenter defaultCenter]
             postNotificationName:@"requestQuitSEBOrSession" object:self];
            return;
        };
        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))remoteProctoringDisclaimerHandler];
        return;
    }
    
    if (browserMediaCaptureScreen || screenProctoringEnable) {
        if (@available(macOS 10.15, *)) {
            NSString *accessibilityPermissionsTitleString = @"";
            NSString *accessibilityPermissionsMessageString = @"";
            if (screenProctoringEnable) {
                // Check if also Accessibility permissions need to be granted
                NSDictionary *options = @{(__bridge id)
                                          kAXTrustedCheckOptionPrompt : @NO};
                if (!AXIsProcessTrustedWithOptions((CFDictionaryRef)options)) {
                    accessibilityPermissionsTitleString = accessibilityTitleString;
                    accessibilityPermissionsMessageString = [NSString stringWithFormat:@"\n\n%@", self.accessibilityMessageString];
                }
            }
            if (@available(macOS 11, *)) {
                if (!CGPreflightScreenCaptureAccess()) {
                    screenCapturePermissionsRequested = YES;
                    if (self.examSession && self.secureClientSession) {
                        // When running an exam session and the client session is secure (has quit pw set), we need to quit the exam session first
                        // but the user or an exam admin will have to quit SEB from the client session manually
                        NSAlert *modalAlert = [self newAlert];
                        [modalAlert setMessageText:[NSString stringWithFormat:@"%@%@", NSLocalizedString(@"Permissions Required for Screen Capture", @""), accessibilityPermissionsTitleString]];
                        [modalAlert setInformativeText:[NSString stringWithFormat:@"%@%@", [NSString stringWithFormat:NSLocalizedString(@"For this exam session, screen capturing is required. You need to authorize Screen Recording for %@ in System Settings / Security & Privacy%@. Then restart %@ and your exam.", @""), SEBFullAppNameClassic, [NSString stringWithFormat:NSLocalizedString(@" (after quitting %@)", @""), SEBShortAppName], SEBShortAppName], accessibilityPermissionsMessageString]];
                        [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit Session", @"")];
                        [modalAlert setAlertStyle:NSAlertStyleCritical];
                        void (^permissionsForProctoringHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                            [self removeAlertWindow:modalAlert.window];
                            [[NSNotificationCenter defaultCenter]
                             postNotificationName:@"requestQuitSEBOrSession" object:self];
                        };
                        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))permissionsForProctoringHandler];
                        return;
                    } else {
                        [[NSNotificationCenter defaultCenter]
                         postNotificationName:@"requestQuitSEBOrSession" object:self];
                        return;
                    }
                }
            }
        }
    }
    
    void (^conditionallyStartProctoring)(void);
    conditionallyStartProctoring =
    ^{
        // OK action handler
        void (^startRemoteProctoringOK)(void) =
        ^{
            if (screenProctoringEnable) {
                
            }
            if (zoomEnable) {
                [self openZoomView];
                [self.zoomController openZoomWithSender:self];
            }
            // Continue starting the exam session
            [self conditionallyStartAACWithCallback:callback selector:selector];
        };
        
        void (^conditionallyStartZoomProctoring)(void);
        conditionallyStartZoomProctoring =
        ^{
            if (zoomEnable) {
                // Check if previous SEB session already had proctoring active
                if (self.previousSessionZoomEnabled) {
                    run_on_ui_thread(startRemoteProctoringOK);
                } else {
                    NSAlert *modalAlert = [self newAlert];
                    [modalAlert setMessageText:NSLocalizedString(@"Remote Proctoring Session", @"")];
                    [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"The current session will be remote proctored using a live video and audio stream, which is sent to an individually configured server. Ask your examinator about their privacy policy. %@ itself doesn't connect to any centralized %@ proctoring server, your exam provider decides which proctoring service/server to use.", @""), SEBShortAppName, SEBShortAppName]];
                    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                    [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
                    [modalAlert setAlertStyle:NSAlertStyleWarning];
                    void (^remoteProctoringDisclaimerHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                        [self removeAlertWindow:modalAlert.window];
                        switch(answer)
                        {
                            case NSAlertFirstButtonReturn:
                            {
                                run_on_ui_thread(startRemoteProctoringOK);
                                return;
                            }
                                
                            case NSAlertSecondButtonReturn:
                            {
                                [[NSNotificationCenter defaultCenter]
                                 postNotificationName:@"requestQuitSEBOrSession" object:self];
                                return;
                            }
                                
                            default:
                                // Can get invoked in case of NSModalResponseStop=-1000 or NSModalResponseAbort=-1001
                            {
                                DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld. Canceling session with enabled remote proctoring.", (long)answer);
                                [self requestedRestart];
                                return;
                            }
                        }
                    };
                    [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))remoteProctoringDisclaimerHandler];
                    return;
                }
            } else {
                // Continue starting the exam session
                startRemoteProctoringOK();
            }
        };
        
        void (^conditionallyStartScreenProctoring)(void);
        conditionallyStartScreenProctoring =
        ^{
            if (screenProctoringEnable) {
                NSDictionary *options = @{(__bridge id)
                                          kAXTrustedCheckOptionPrompt : @NO};
                NSAlert *modalAlert = nil;
                if (!AXIsProcessTrustedWithOptions((CFDictionaryRef)options)) {
                    DDLogWarn(@"SEB is not trusted in Privacy / Accessibility, prompt the user to grant access in Settings");
                    modalAlert = [self newAlert];
                    [modalAlert setMessageText:NSLocalizedString(@"Accessibility Permissions Required", @"")];
                    [modalAlert setInformativeText:[NSString stringWithFormat:@"%@ %@", self.accessibilityMessageString, [NSString stringWithFormat:NSLocalizedString(@"Then restart %@/the exam.", @""), SEBShortAppName]]];
                    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                    [modalAlert setAlertStyle:NSAlertStyleCritical];
                    [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow
                      completionHandler:^(NSModalResponse returnCode) {
                        [self removeAlertWindow:modalAlert.window];
                        NSDictionary *options = @{(__bridge id)
                                                  kAXTrustedCheckOptionPrompt : @YES};
                        if (AXIsProcessTrustedWithOptions((CFDictionaryRef)options)) {
                            conditionallyStartZoomProctoring();
                        } else {
                            // Switch the kiosk mode off and override settings for menu bar: Show it while prefs are open
                            [preferences setSecureBool:NO forKey:@"org_safeexambrowser_elevateWindowLevels"];
                            [self switchKioskModeAppsAllowed:YES overrideShowMenuBar:YES];
                            // Close the black background covering windows
                            [self closeCapWindows];
                            
                            NSAlert *modalAlert = [self newAlert];
                            [modalAlert setMessageText:NSLocalizedString(@"Waiting for Accessibility Permissions", @"")];
                            [modalAlert setInformativeText:[NSString stringWithFormat:@"%@ %@", self.accessibilityMessageString, [NSString stringWithFormat:NSLocalizedString(@"Then restart %@/the exam.", @""), SEBShortAppName]]];
                            [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
                            [modalAlert setAlertStyle:NSAlertStyleCritical];
                            [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow
                              completionHandler:^(NSModalResponse returnCode) {
                                [[NSNotificationCenter defaultCenter]
                                 postNotificationName:@"requestQuitSEBOrSession" object:self];
                            }];
                        }
                    }];
                    return;
                }
            }
            conditionallyStartZoomProctoring();
        };
        

        if (screenProctoringEnable) {
            // Check if previous SEB session already had proctoring active
            if (!self.previousSessionScreenProctoringEnabled) {
                NSAlert *modalAlert = [self newAlert];
                [modalAlert setMessageText:NSLocalizedString(@"Screen Proctoring Session", @"")];
                [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"Your screen will be recorded during this exam in accordance with the specifications and data privacy regulations of your exam provider. If you have any questions, please contact your exam provider.%@", @""), isETHExam ? @"":[NSString stringWithFormat:NSLocalizedString(@" %@ itself doesn't connect to any centralized %@ screen proctoring server, your exam provider decides which proctoring service/server to use.", @""), SEBShortAppName, SEBShortAppName]]];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
                [modalAlert setAlertStyle:NSAlertStyleWarning];
                void (^remoteProctoringDisclaimerHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                    [self removeAlertWindow:modalAlert.window];
                    switch(answer)
                    {
                        case NSAlertFirstButtonReturn:
                        {
                            self.previousSessionScreenProctoringEnabled = YES;
                            run_on_ui_thread(conditionallyStartScreenProctoring);
                            return;
                        }
                            
                        case NSAlertSecondButtonReturn:
                        {
                            [[NSNotificationCenter defaultCenter]
                             postNotificationName:@"requestQuitSEBOrSession" object:self];
                            return;
                        }
                            
                        default:
                            // Can get invoked in case of NSModalResponseStop=-1000 or NSModalResponseAbort=-1001
                        {
                            DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld. Canceling session with enabled screen proctoring.", (long)answer);
                            [self requestedRestart];
                            return;
                        }
                    }
                };
                [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))remoteProctoringDisclaimerHandler];
                return;
            }
        } else {
            self.previousSessionScreenProctoringEnabled = NO;
        }
        conditionallyStartScreenProctoring();
    };
    
    if (browserMediaCaptureMicrophone ||
        browserMediaCaptureCamera) {
        
        if (@available(macOS 10.14, *)) {
            AVAuthorizationStatus audioAuthorization = [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio];
            AVAuthorizationStatus videoAuthorization = [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeVideo];
            if (((browserMediaCaptureMicrophone && (audioAuthorization != AVAuthorizationStatusAuthorized)) ||
                 (browserMediaCaptureCamera && (videoAuthorization != AVAuthorizationStatusAuthorized)))) {
                
                NSMutableArray <AVMediaType> *authorizationAccessRequests = [NSMutableArray new];
                
                NSString *microphone = (proctoringSession || browserMediaCaptureMicrophone) && audioAuthorization != AVAuthorizationStatusAuthorized ? NSLocalizedString(@"microphone", @"") : @"";
                NSString *camera = @"";
                if ((proctoringSession || browserMediaCaptureCamera) && videoAuthorization != AVAuthorizationStatusAuthorized) {
                    camera = [NSString stringWithFormat:@"%@%@", NSLocalizedString(@"camera", @""), microphone.length > 0 ? NSLocalizedString(@" and ", @"") : @""];
                    [authorizationAccessRequests addObject:AVMediaTypeVideo];
                }
                if (microphone.length > 0) {
                    [authorizationAccessRequests addObject:AVMediaTypeAudio];
                }
                NSString *permissionsRequiredFor = [NSString stringWithFormat:@"%@%@%@",
                                                    proctoringSession ? NSLocalizedString(@"remote proctoring", @"") : @"",
                                                    proctoringSession && webApplications ? NSLocalizedString(@" and ", @"") : @"",
                                                    webApplications ? NSLocalizedString(@"web applications", @"") : @""];
                NSString *resolveSuggestion;
                NSString *resolveSuggestion2;
                NSString *message;
                if ((browserMediaCaptureCamera && videoAuthorization == AVAuthorizationStatusDenied) ||
                    (browserMediaCaptureMicrophone && audioAuthorization == AVAuthorizationStatusDenied)) {
                    resolveSuggestion = NSLocalizedString(@"in System Preferences ", @"");
                    resolveSuggestion2 = [NSString stringWithFormat:NSLocalizedString(@"return to %@ and re", @""), SEBShortAppName];
                } else {
                    resolveSuggestion = @"";
                    resolveSuggestion2 = @"";
                }
                if ((browserMediaCaptureCamera && videoAuthorization == AVAuthorizationStatusRestricted) ||
                    (browserMediaCaptureMicrophone && audioAuthorization == AVAuthorizationStatusRestricted)) {
                    message = [NSString stringWithFormat:NSLocalizedString(@"For this session, %@%@ access for %@ is required. On this device, %@%@ access is restricted. Ask your IT support to provide you a device without these restrictions.", @""), camera, microphone, permissionsRequiredFor, camera, microphone];
                } else {
                    message = [NSString stringWithFormat:NSLocalizedString(@"For this session, %@%@ access for %@ is required. You need to authorize %@%@ access %@before you can %@start the session.", @""), camera, microphone, permissionsRequiredFor, camera, microphone, resolveSuggestion, resolveSuggestion2];
                }
                NSString *firstButtonTitle = ((browserMediaCaptureCamera && videoAuthorization == AVAuthorizationStatusDenied) ||
                                              (browserMediaCaptureMicrophone && audioAuthorization == AVAuthorizationStatusDenied)) ? NSLocalizedString(@"System Preferences", @"") : NSLocalizedString(@"OK", @"");
                
                NSAlert *modalAlert = [self newAlert];
                [modalAlert setMessageText:[NSString stringWithFormat:NSLocalizedString(@"Permissions Required for %@", @""), permissionsRequiredFor.localizedCapitalizedString]];
                [modalAlert setInformativeText:message];
                [modalAlert addButtonWithTitle:firstButtonTitle];
                if (NSUserDefaults.userDefaultsPrivate) {
                    [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
                }
                [modalAlert setAlertStyle:NSAlertStyleCritical];
                
                // Block for requesting access to camera and microphone
                void (^permissionsForProctoringHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                    [self removeAlertWindow:modalAlert.window];
                    switch(answer)
                    {
                        case NSAlertFirstButtonReturn:
                        {
                            if ((browserMediaCaptureCamera && videoAuthorization == AVAuthorizationStatusDenied) ||
                                (browserMediaCaptureMicrophone && audioAuthorization == AVAuthorizationStatusDenied)) {
                                [[NSWorkspace sharedWorkspace] openURL: [NSURL URLWithString:pathToSecurityPrivacyPreferences]];
                                [[NSNotificationCenter defaultCenter]
                                 postNotificationName:@"requestQuitSEBOrSession" object:self];
                                return;
                            }
                            [AVCaptureDevice requestAccessForMediaType:authorizationAccessRequests[0] completionHandler:^(BOOL granted) {
                                if (granted){
                                    DDLogInfo(@"Granted access to %@", authorizationAccessRequests[0]);
                                    
                                    if (authorizationAccessRequests.count > 1) {
                                        [AVCaptureDevice requestAccessForMediaType:authorizationAccessRequests[1] completionHandler:^(BOOL granted) {
                                            if (granted){
                                                DDLogInfo(@"Granted access to %@", authorizationAccessRequests[1]);
                                                
                                                run_on_ui_thread(conditionallyStartProctoring);
                                                
                                            } else {
                                                DDLogError(@"Not granted access to %@", authorizationAccessRequests[1]);
                                                [[NSNotificationCenter defaultCenter]
                                                 postNotificationName:@"requestQuitSEBOrSession" object:self];
                                            }
                                        }];
                                    } else {
                                        run_on_ui_thread(conditionallyStartProctoring);
                                    }
                                    return;
                                    
                                } else {
                                    DDLogError(@"Not granted access to %@", authorizationAccessRequests[0]);
                                    [[NSNotificationCenter defaultCenter]
                                     postNotificationName:@"requestQuitSEBOrSession" object:self];
                                }
                            }];
                            return;
                        }
                            
                        case NSAlertSecondButtonReturn:
                        {
                            [[NSNotificationCenter defaultCenter]
                             postNotificationName:@"requestQuitSEBOrSession" object:self];
                            return;
                        }
                            
                        default:
                            // Can get invoked in case of NSModalResponseStop=-1000 or NSModalResponseAbort=-1001
                        {
                            DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld. Canceling session with enabled remote proctoring.", (long)answer);
                            [self requestedRestart];
                            return;
                        }
                    }
                    
                };
                // End of Block
                
                [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))permissionsForProctoringHandler];
                return;
                
            } else {
                run_on_ui_thread(conditionallyStartProctoring);
                return;
            }
        } else {
            run_on_ui_thread(conditionallyStartProctoring);
            return;
        }
    } else {
        self.previousSessionZoomEnabled = NO;
    }
    // Continue starting the exam session
    run_on_ui_thread(conditionallyStartProctoring);
}


- (void) conditionallyStartAACWithCallback:(id)callback selector:(SEL)selector
{
    if (!_conditionalInitAfterProcessesChecked) {
        _conditionalInitAfterProcessesChecked = YES;
        /// Early kiosk mode setup (as these actions might take some time)
        
        /// When running on macOS 10.15.4 or newer, use AAC
        if (@available(macOS 10.15.4, *)) {
            NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
            DDLogDebug(@"Running on macOS 10.15.4 or newer, may use AAC if allowed in current settings.");
            [self updateAACAvailablility];
            if (_blinkeredEarlyCoversActive && _isAACEnabled == NO) {
                // The caps are this launch's early session covers, not leftovers from a
                // previous session — closing them here would flash the desktop mid-launch.
                DDLogInfo(@"Keeping early cover windows up (no AAC)");
            } else {
                DDLogDebug(@"_isAACEnabled == true, attempting to close cap (background covering) windows, which might have been open from a previous SEB session.");
                [self closeCapWindows];
            }
            DDLogInfo(@"isAACEnabled = %hhd", _isAACEnabled);
            if (_isAACEnabled == YES && _wasAACEnabled == NO) {
                void (^startAssessmentMode)(void) =
                ^{
                    NSApp.presentationOptions |= (NSApplicationPresentationDisableForceQuit | NSApplicationPresentationHideDock);
                    DDLogDebug(@"_isAACEnabled = true && _wasAACEnabled == false");
                    AssessmentModeManager *assessmentModeManager = [[AssessmentModeManager alloc] initWithCallback:callback selector:selector fallback:NO];
                    self.assessmentModeManager = assessmentModeManager;
                    self.assessmentModeManager.delegate = self;
                    NSArray *permittedProcesses = [ProcessManager sharedProcessManager].permittedProcesses;
                    AEAssessmentConfiguration *configuration = [[AEAssessmentConfiguration alloc] initWithPermittedApplications:permittedProcesses];
                    if (@available(macOS 12.0, *)) {
                        if (permittedProcesses.count > 0 &&
                            configuration.configurationsByApplication.count != permittedProcesses.count) {
                            // Not all permitted applications were found or could be started, inform user and quit
                            DDLogError(@"Some permitted apps were not available, SEB will quit");
                            [self showModalQuitAlertTitle:NSLocalizedString(@"Additional Applications Not Available", @"")
                                                     text:[NSString stringWithFormat:@"%@\n%@\n%@", NSLocalizedString(@"This exam session requires the following additional applications to be available:", @""), [permittedProcesses valueForKeyPath:@"title"] , [NSString stringWithFormat:NSLocalizedString(@"%@ will quit now, install the required apps and then restart this exam.", @""), SEBShortAppName]]];
                            return;
                        }
                        if (permittedProcesses.count > 0 &&
                            ![self.assessmentConfigurationManager removeSavedAppWindowStateWithPermittedApplications:permittedProcesses]) {
                            DDLogError(@"Could not remove saved window state for permitted apps, SEB will quit");
                            [self showModalQuitAlertTitle:NSLocalizedString(@"Could Not Access Data of Additional Apps", @"")
                                                     text:[NSString stringWithFormat:NSLocalizedString(@"This exam session requires using additional applications. You have to allow access to their data, as %@ has to remove the saved state of previously open document windows in these apps (%@ is not accessing any of your data created in these apps). %@ will quit now, restart the exam and grant access to the data of additional apps next time.", @""), SEBShortAppName, SEBShortAppName, SEBShortAppName]];
                            return;
                        }
                    }
//                    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_enableScreenProctoring"]) {
//                        if ([configuration respondsToSelector: NSSelectorFromString(@"setAllowsScreenshots:")]) {
//                            DDLogDebug(@"AAC with screen proctoring enabled: Use new API to allow screen shots");
//
//                            SEL selector = NSSelectorFromString(@"setAllowsScreenshots:");
//                            IMP imp = [configuration methodForSelector:selector];
//                            void (*func)(id, SEL, BOOL) = (void *)imp;
//                            func(configuration, selector, YES);
//                        } else {
//                            DDLogWarn(@"AAC with screen proctoring enabled: API to allow screen shots is not available.");
//                        }
//                    }
                    if ([self.assessmentModeManager beginAssessmentModeWithConfiguration:configuration] == NO) {
                        [self assessmentSessionDidEndWithCallback:callback selector:selector quittingToAssessmentMode:NO];
                    }
                };
                
                // Save current string from pasteboard for pasting start URL in Preferences Window
                // and clear pasteboard (latter acutally isn't necessary for AAC)
                [self clearPasteboardSavingCurrentString];
                
                if (@available(macOS 12.1, *)) {
                    // DNS pre-pinning not necessary on macOS 12.1 or newer, as the AAC bug is fixed there
                } else {
                    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_aacDnsPrePinning"]) {
                        NSArray *permittedDomains = SEBURLFilter.sharedSEBURLFilter.permittedDomains;
                        if (permittedDomains.count == 0) {
                            NSString *urlText = self.sessionState.startURL.absoluteString;
                            if (urlText.length == 0) {
                                urlText = SEBStartPage;
                            }
                            NSURL *startURL = [NSURL URLWithString:urlText];
                            permittedDomains = @[startURL.host];
                        }
                        BOOL result;
                        for (NSString *permittedDomain in permittedDomains) {
                            NSString *host = permittedDomain;
                            if ([permittedDomain hasPrefix:@"."] && permittedDomain.length > 1) {
                                host = [permittedDomain substringFromIndex:1];
                            }
                            CFHostRef hostRef;
                            hostRef = CFHostCreateWithName(kCFAllocatorDefault, (__bridge CFStringRef)host);
                            if (hostRef) {
                                result = CFHostStartInfoResolution(hostRef, kCFHostAddresses, NULL); // pass an error instead of NULL here to find out why it failed
                                if (result) {
                                    DDLogDebug(@"Performed DNS pre-pinning of host %@", host);
                                } else {
                                    DDLogDebug(@"DNS pre-pinning of host %@ failed", host);
                                }
                            }
                        }
                    }
                }
                startAssessmentMode();
                return;
            } else if (_isAACEnabled == NO && _wasAACEnabled == YES) {
                DDLogDebug(@"_isAACEnabled = false && _wasAACEnabled == true");
                [self.assessmentModeManager endAssessmentModeWithCallback:callback selector:selector quittingToAssessmentMode:NO];
                return;
            }
        } else {
            _isAACEnabled = NO;
        }
    }
    [self initSEBProcessesCheckedWithCallback:callback selector:selector];
}


/// Assessment Mode Delegate Methods

- (void) assessmentSessionWillBegin
{
    DDLogDebug(@"%s", __FUNCTION__);
    [self.hudController showHUDProgressIndicator];
}

- (void) assessmentSessionWillEnd
{
    DDLogDebug(@"%s", __FUNCTION__);
    [self.hudController showHUDProgressIndicator];
}

- (void) assessmentSessionDidBeginWithCallback:(id)callback
                                      selector:(SEL)selector
                                      fallback:(BOOL)fallback
{
    _isAACEnabled = YES;
    _wasAACEnabled = YES;
    [NSMenu setMenuBarVisible:NO];
    [self.hudController hideHUDProgressIndicator];
    [self.assessmentConfigurationManager autostartAppsWithPermittedApplications:[ProcessManager sharedProcessManager].permittedProcesses];
    [self initSEBProcessesCheckedWithCallback:callback selector:selector];
}

- (void) assessmentSessionFailedToBeginWithError:(NSError *)error
                                        callback:(id)callback
                                        selector:(SEL)selector
                                        fallback:(BOOL)fallback
{
    [self.hudController hideHUDProgressIndicator];
    DDLogError(@"Could not start AAC Assessment Mode, falling back to SEB kiosk mode. Error: %@", error);
    // Use SEB kiosk mode
    _overrideAAC = YES;
    _isAACEnabled = NO;
    _wasAACEnabled = NO;
    [self initSEBProcessesCheckedWithCallback:callback selector:selector];
}


- (void) assessmentSessionDidEndWithCallback:(id)callback
                                    selector:(SEL)selector
                    quittingToAssessmentMode:(BOOL)quittingToAssessmentMode
{
    _wasAACEnabled = NO;
    [self.hudController hideHUDProgressIndicator];
    if (_isTerminating) {
        DDLogDebug(@"%s, continue with callback: %@ selector: %@", __FUNCTION__, callback, NSStringFromSelector(selector));
        IMP imp = [callback methodForSelector:selector];
        void (*func)(id, SEL) = (void *)imp;
        func(callback, selector);
    } else {
        DDLogDebug(@"%s, continue with [self initSEBProcessesCheckedWithCallback:%@ selector: %@]", __FUNCTION__, callback, NSStringFromSelector(selector));
        [self initSEBProcessesCheckedWithCallback:callback selector:selector];
    }
}

- (void) assessmentSessionWasInterruptedWithError:(NSError *)error
{
    [self.hudController hideHUDProgressIndicator];
    DDLogError(@"AAC Assessment Mode was interrupted with error: %@", error);
    
    // Lock the exam down
    
    // Save current time for information about when Guided Access was switched off
    _didResignActiveTime = [NSDate date];
    
    // If there wasn't a lockdown covering view openend yet, initialize it
    [self openLockdownWindows];
    [self appendErrorString:[NSString stringWithFormat:@"%@%@!\n", NSLocalizedString(@"Assessment Mode was interrupted with error: ", @""), error] withTime:_didResignActiveTime repeated:NO];
}


void run_on_ui_thread(dispatch_block_t block)
{
    if ([NSThread isMainThread])
        block();
    else
        dispatch_sync(dispatch_get_main_queue(), block);
}


- (void) initSEBProcessesCheckedWithCallback:(id)callback selector:(SEL)selector
{
    if (_openingSettings) {
        DDLogDebug(@"OpeningSettings = true, abort %s", __FUNCTION__);
        return;
    }
    DDLogDebug(@"%s callback: %@ selector: %@", __FUNCTION__, callback, NSStringFromSelector(selector));
    
    /// Early kiosk mode setup (as these actions might take some time)
    
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if (_isAACEnabled == NO) {
        DDLogDebug(@"%s: isAACEnabled = false, using SEB kiosk mode", __FUNCTION__);
        
        // Hide all other applications
        [[NSWorkspace sharedWorkspace] performSelectorOnMainThread:@selector(hideOtherApplications)
                                                        withObject:NULL waitUntilDone:YES];        
    }
    allowScreenCapture = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowScreenCapture"];
    allowDictionaryLookup = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDictionaryLookup"];
    allowOpenAndSavePanel = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowOpenAndSavePanel"];
    allowShareSheet = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowShareSheet"];
    voiceOverDisabled = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_accessibilityFeatureVoiceOver"] == AccessibilityFeaturePolicyDisable;
    allowSpellCheck = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowSpellCheck"];

    // Switch off display mirroring and find main active screen according to settings
    [self conditionallyTerminateDisplayMirroring];
    
    if (_isAACEnabled == NO) {
        
        // Switch off Siri and dictation if not allowed in settings
        [self conditionallyDisableSpeechInput];
        
        // Switch off TouchBar features
        [self disableTouchBarFeatures];
        
        // Switch to kiosk mode by setting the proper presentation options
        [self setElevateWindowLevels];
        [self startKioskMode];
        
        // Clear pasteboard and save current string for pasting start URL in Preferences Window
        [self clearPasteboardSavingCurrentString];
        
        // Check if the Force Quit window is open
        if (![self forceQuitWindowCheckContinue]) {
            return;
        }
        
        // Run watchdog event for windows and events which need to be observed
        // on the main (UI!) thread once, to initialize
        dispatch_async(dispatch_get_main_queue(), ^{
            [self windowWatcher];
        });
    }
    
    /// Update URL filter flags and rules
    [[SEBURLFilter sharedSEBURLFilter] updateFilterRulesWithStartURL:self.startURL];
    // Update URL filter ignore rules
    [[SEBURLFilter sharedSEBURLFilter] updateIgnoreRuleList];
    
    // Set up and open SEB Dock
    [self openSEBDock];
    self.browserController.dockController = self.dockController;
    self.dockController.dockButtonDelegate = self;
        
    // Continue starting the exam session
    IMP imp = [callback methodForSelector:selector];
    void (*func)(id, SEL) = (void *)imp;
    func(callback, selector);
}


- (void) startSystemMonitoring
{
    // Get all running processes, including daemons
    NSArray *allRunningProcesses = [self getProcessArray];
    NSArray *allRunningProcessNames = [allRunningProcesses valueForKey:@"name"];
    DDLogInfo(@"There are %lu running BSD processes: \n%@", (unsigned long)allRunningProcessNames.count, allRunningProcessNames);
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    allowDictation = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDictation"];

    if (_isAACEnabled == NO) {
        // Check for activated screen sharing if settings demand it
        allowScreenSharing = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowScreenSharing"] &&
        ![preferences secureBoolForKey:@"org_safeexambrowser_SEB_screenSharingMacEnforceBlocked"];
        allowSiri = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowSiri"];
        
        if (!allowScreenSharing &&
            ([allRunningProcessNames containsObject:screenSharingAgent] ||
             [allRunningProcessNames containsObject:AppleVNCAgent]))
        {
            // Screen sharing is active
            DDLogError(@"Screen Sharing Detected, SEB will quit");
            [self showModalQuitAlertTitle:NSLocalizedString(@"Screen Sharing Detected!", @"")
                                     text:[NSString stringWithFormat:@"%@\n\n%@",
                                           [NSString stringWithFormat:NSLocalizedString(@"You are not allowed to have screen sharing active while running %@. Restart %@ after switching screen sharing off.", @""), SEBShortAppName, SEBShortAppName],
                                           [NSString stringWithFormat:NSLocalizedString(@"To avoid that %@ locks itself during an exam when it detects that screen sharing started, it's best to switch off 'Screen Sharing' and 'Remote Management' in System Settings/Sharing. You can also ask your network administrators to block ports used for the VNC protocol.", @""), SEBShortAppName]]];
            return;
        }
        
        if (!allowSiri &&
            [allRunningProcessNames containsObject:SiriService] &&
            [[preferences valueForDefaultsDomain:SiriDefaultsDomain key:SiriDefaultsKey] boolValue])
        {
            // Siri is active
            DDLogError(@"Siri Detected, SEB will quit");
            [self showModalQuitAlertTitle:NSLocalizedString(@"Siri Detected!", @"")
                                     text:[NSString stringWithFormat:NSLocalizedString(@"You are not allowed to have Siri enabled while running %@. Restart %@ after switching Siri off in System Settings/Siri.", @""), SEBShortAppName, SEBShortAppName]];
            return;
        }
        
        if (!allowDictation &&
            [allRunningProcessNames containsObject:DictationProcess] &&
            ([[preferences valueForDefaultsDomain:DictationDefaultsDomain key:DictationDefaultsKey] boolValue] ||
             [[preferences valueForDefaultsDomain:RemoteDictationDefaultsDomain key:RemoteDictationDefaultsKey] boolValue]))
        {
            // Dictation is active
            DDLogError(@"Dictation Detected, SEB will quit");
            [self showModalQuitAlertTitle:NSLocalizedString(@"Dictation Detected!", @"")
                                     text:[NSString stringWithFormat:NSLocalizedString(@"You are not allowed to have dictation enabled while running %@. Restart %@ after switching dictation off in System Settings/Keyboard/Dictation.", @""), SEBShortAppName, SEBShortAppName]];
            return;
        }
    }
    [self startProcessWatcher];
    [self startWindowWatcher];
}


- (void)showModalQuitAlertTitle:(NSString *)title text:(NSString *)text
{
    NSAlert *modalAlert = [self newAlert];
    [modalAlert setMessageText:title];
    [modalAlert setInformativeText:text];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
    [modalAlert setAlertStyle:NSAlertStyleCritical];
    void (^quitAlertConfirmed)(NSModalResponse) = ^void (NSModalResponse answer) {
        DDLogDebug(@"%s: %@: NSModalResponse: %ld", __FUNCTION__, title, (long)answer);
        [self removeAlertWindow:modalAlert.window];
        [self requestedExit:nil]; // Quit SEB
    };
    [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))quitAlertConfirmed];
}


#pragma mark - After Start Initialization

// Perform actions which require that SEB has finished setting up and has opened its windows
- (void) performAfterStartActions:(NSNotification *)notification
{
    DDLogDebug(@"%s", __FUNCTION__);
    DDLogInfo(@"Performing after start actions");
    
    if (_isAACEnabled == NO) {
        // Check for command key being held down
        [self appSwitcherCheck];

        // Reinforce the kiosk mode
        [self requestedReinforceKioskMode:nil];

        // P1 Bug-A: arm paint recovery (wake/occlusion/periodic observers + the content-revealed hook).
        // The REVEAL check does NOT run here — performAfterStartActions fires while the window is still
        // deliberately held black (blinkeredHoldContentUntilFirstPaint), which would false-fire on every
        // launch. It runs from blinkeredContentRevealed: when content is actually shown.
        [self blinkeredArmPaintRecovery];
    }

    if ([[MyGlobals sharedMyGlobals] preferencesReset] == YES) {
        // Blinkered: local client preferences are disposable — device pairing lives in
        // agent.json and every session is configured from its own .seb. The integrity
        // check resets them to defaults (e.g. after an app update writes them in a newer
        // format, or an interrupted write), which is harmless here. Suppress the alarming
        // "settings have been reset — ask your exam supporter" alert that would otherwise
        // confront the parent/student on launch; just log it and clear the flag.
        DDLogError(@"Blinkered: local settings were reset to defaults — suppressing the user-facing alert");
        [[MyGlobals sharedMyGlobals] setPreferencesReset:NO];
    }
    
    if (_isAACEnabled == NO) {
        // Check if the Force Quit window is open
        if (![self forceQuitWindowCheckContinue]) {
            return;
        }
    }
    
    if ([MyGlobals sharedMyGlobals].reconfiguredWhileStarting) {
        // Show alert that SEB was reconfigured
        NSAlert *modalAlert = [self newAlert];
        [modalAlert setMessageText:[NSString stringWithFormat:NSLocalizedString(@"%@ Re-Configured", @""), SEBShortAppName]];
         [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"New settings have been saved, they will be used when you start %@ next time again. Do you want to continue working with %@ or quit for now?", @""), SEBShortAppName, SEBShortAppName]];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"Continue", @"")];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
        void (^reconfiguredAnswer)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self removeAlertWindow:modalAlert.window];
            switch(answer)
            {
                case NSAlertFirstButtonReturn:
                    
                    break; //Continue running SEB
                    
                case NSAlertSecondButtonReturn:
                {
                    [self performSelector:@selector(requestedExit:) withObject: nil afterDelay: 3];
                }
            }
        };
        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))reconfiguredAnswer];
    }
    
    // Set flag that SEB is initialized: Now showing alerts is allowed
    [[MyGlobals sharedMyGlobals] setFinishedInitializing:YES];
}


#pragma mark - Logger Initialization

// Initializes a temporary logger unconditionally with the Debug log level
// and the standard log file path, so SEB can log startup events before
// settings are initialized
- (void) initializeTemporaryLogger
{
    _myLogger = [MyGlobals initializeFileLoggerWithDirectory:nil];
    [DDLog addLogger:_myLogger];
    
    DDLogInfo(@"---------- STARTING UP SEB - INITIALIZE SETTINGS -------------");
    DDLogInfo(@"(log after start up is finished may continue in another file, according to current settings)");
    [MyGlobals logSystemInfo];
}

- (void) initializeLogger
{
    // Initialize file logger if logging enabled
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_enableLogging"] == NO) {
        [DDLog removeLogger:_myLogger];
        _myLogger = nil;
        if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_sebMode"] == sebModeSebServer) {
            [DDLog removeLogger:ServerLogger.sharedInstance];
        }
    } else {
        //Set log directory
        NSString *logPath = [[NSUserDefaults standardUserDefaults] secureStringForKey:@"org_safeexambrowser_SEB_logDirectoryOSX"];
        [DDLog removeLogger:_myLogger];
        if (logPath.length == 0) {
            // No log directory indicated: We use the standard one
            logPath = nil;
        } else {
            logPath = [logPath stringByExpandingTildeInPath];
            // Add subdirectory with the name of the computer
        }
        _myLogger = [MyGlobals initializeFileLoggerWithDirectory:logPath];
        [DDLog addLogger:_myLogger];
        
        if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_sebMode"] == sebModeSebServer ||
            _establishingSEBServerConnection || _sebServerConnectionEstablished) {
            if (![DDLog.allLoggers containsObject:ServerLogger.sharedInstance]) {
                [DDLog addLogger:ServerLogger.sharedInstance];
                ServerLogger.sharedInstance.delegate = self;
            }
        }
        
        DDLogInfo(@"---------- INITIALIZING SEB - STARTING SESSION -------------");
        [MyGlobals logSystemInfo];
    }
}


- (void) sendLogEventWithLogLevel:(NSUInteger)logLevel
                        timestamp:(NSString *)timestamp
                     numericValue:(double)numericValue
                          message:(NSString *)message
{
    [self.serverController sendLogEventWithLogLevel:logLevel timestamp:timestamp numericValue:numericValue message:message];
}


#pragma mark - Process Monitoring

- (NSArray *) getProcessNameArray {
    NSMutableArray *ProcList = [[NSMutableArray alloc] init];
    
    kinfo_proc *mylist;
    size_t mycount = 0;
    mylist = (kinfo_proc *)malloc(sizeof(kinfo_proc));
    GetBSDProcessList(&mylist, &mycount);
    BOOL numberRunningBSDProcessesChanged = false;
    if ((NSUInteger)mycount != lastNumberRunningBSDProcesses) {
        numberRunningBSDProcessesChanged = true;
        lastNumberRunningBSDProcesses = (NSUInteger)mycount;
        DDLogVerbose(@"There are %lu running BSD processes.", (unsigned long)lastNumberRunningBSDProcesses);
    }
    int k;
    for(k = 0; k < mycount; k++) {
        kinfo_proc *proc = NULL;
        proc = &mylist[k];
        pid_t processPID = proc-> kp_proc.p_pid;
        NSString * processName = [self getProcessName:processPID];
        [ProcList addObject:processName];
        if (numberRunningBSDProcessesChanged) {
            DDLogVerbose(@"PID: %d - Name: %s", proc->kp_proc.p_pid, proc-> kp_proc.p_comm);
        }
    }
    free(mylist);
    
    return ProcList;
}


- (NSArray <NSDictionary *>*) getProcessArray {
    NSMutableArray *ProcList = [[NSMutableArray alloc] init];
    
    kinfo_proc *mylist;
    size_t mycount = 0;
    mylist = (kinfo_proc *)malloc(sizeof(kinfo_proc));
    GetBSDProcessList(&mylist, &mycount);
    BOOL numberRunningBSDProcessesChanged = false;
    if ((NSUInteger)mycount != lastNumberRunningBSDProcesses) {
        numberRunningBSDProcessesChanged = true;
        lastNumberRunningBSDProcesses = (NSUInteger)mycount;
        DDLogVerbose(@"There are %lu running BSD processes.", (unsigned long)lastNumberRunningBSDProcesses);
    }
    NSDictionary *processDetails;
    int k;
    for(k = 0; k < mycount; k++) {
        kinfo_proc *proc = NULL;
        proc = &mylist[k];
        pid_t processPID = proc-> kp_proc.p_pid;
        NSString * processName = [self getProcessName:processPID];
        processDetails = @{
                           @"name" : processName,
                           @"PID" : [NSNumber numberWithInt:processPID]
                           };
        [ProcList addObject:processDetails];
        if (numberRunningBSDProcessesChanged) {
            DDLogVerbose(@"PID: %d - Name: %@", processPID, processName);
        }
    }
    free(mylist);
    
    return ProcList;
}



-(NSString*) getProcessName:(pid_t) pid {
    char executablePath[PROC_PIDPATHINFO_MAXSIZE];
    NSString *executableStringPath = [[NSString alloc] init];
    bzero(executablePath, PROC_PIDPATHINFO_MAXSIZE);
    proc_pidpath(pid, executablePath, sizeof(executablePath));
    if (sizeof(executablePath) > 0) {
        executableStringPath = @(executablePath);
    }
    return executableStringPath.lastPathComponent;
}


// Obsolete
- (NSDictionary *) getProcessDictionary {
    NSMutableDictionary *ProcList = [[NSMutableDictionary alloc] init];
    
    kinfo_proc *mylist;
    size_t mycount = 0;
    mylist = (kinfo_proc *)malloc(sizeof(kinfo_proc));
    GetBSDProcessList(&mylist, &mycount);
    BOOL numberRunningBSDProcessesChanged = false;
    if ((NSUInteger)mycount != lastNumberRunningBSDProcesses) {
        numberRunningBSDProcessesChanged = true;
        lastNumberRunningBSDProcesses = (NSUInteger)mycount;
        DDLogVerbose(@"There are %lu running BSD processes: ", (unsigned long)lastNumberRunningBSDProcesses);
    }
    int k;
    for(k = 0; k < mycount; k++) {
        kinfo_proc *proc = NULL;
        proc = &mylist[k];
        NSString *processName = [NSString stringWithFormat: @"%s",proc-> kp_proc.p_comm];
        if (processName == nil) {
            processName = @"";
        }
        [ ProcList setObject: processName forKey: @"name" ];
        [ ProcList setObject: [NSNumber numberWithInt:proc->kp_proc.p_pid] forKey: @"PID"];
    }
    free(mylist);
    
    if (numberRunningBSDProcessesChanged) {
        DDLogVerbose(@"%@", ProcList);
    }
    return ProcList;
}


typedef struct kinfo_proc kinfo_proc;

static int GetBSDProcessList(kinfo_proc **procList, size_t *procCount)
// Returns a list of all BSD processes on the system.  This routine
// allocates the list and puts it in *procList and a count of the
// number of entries in *procCount.  You are responsible for freeing
// this list (use "free" from System framework).
// On success, the function returns 0.
// On error, the function returns a BSD errno value.
{
    int                 err;
    kinfo_proc *        result;
    bool                done;
    static const int    name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    // Declaring name as const requires us to cast it when passing it to
    // sysctl because the prototype doesn't include the const modifier.
    size_t              length;
    
    *procCount = 0;
    
    // We start by calling sysctl with result == NULL and length == 0.
    // That will succeed, and set length to the appropriate length.
    // We then allocate a buffer of that size and call sysctl again
    // with that buffer.  If that succeeds, we're done.  If that fails
    // with ENOMEM, we have to throw away our buffer and loop.  Note
    // that the loop causes use to call sysctl with NULL again; this
    // is necessary because the ENOMEM failure case sets length to
    // the amount of data returned, not the amount of data that
    // could have been returned.
    
    result = NULL;
    done = false;
    do {
        
        // Call sysctl with a NULL buffer.
        
        length = 0;
        err = sysctl( (int *) name, (sizeof(name) / sizeof(*name)) - 1,
                     NULL, &length,
                     NULL, 0);
        if (err == -1) {
            err = errno;
        }
        
        // Allocate an appropriately sized buffer based on the results
        // from the previous call.
        
        if (err == 0) {
            result = malloc(length);
            if (result == NULL) {
                err = ENOMEM;
            }
        }
        
        // Call sysctl again with the new buffer.  If we get an ENOMEM
        // error, toss away our buffer and start again.
        
        if (err == 0) {
            err = sysctl( (int *) name, (sizeof(name) / sizeof(*name)) - 1,
                         result, &length,
                         NULL, 0);
            if (err == -1) {
                err = errno;
            }
            if (err == 0) {
                done = true;
            } else if (err == ENOMEM) {
                free(result);
                result = NULL;
                err = 0;
            }
        }
    } while (err == 0 && ! done);
    
    // Clean up and establish post conditions.
    
    if (err != 0 && result != NULL) {
        free(result);
        result = NULL;
    }
    *procList = result;
    if (err == 0) {
        *procCount = length / sizeof(kinfo_proc);
    }
    
    return err;
}


#pragma mark - Window/Panel Monitoring

// Start the process watcher if it's not yet running
- (void)startProcessWatcher
{
    DDLogDebug(@"%s", __FUNCTION__);
    
    if (!_processWatchTimer) {
        dispatch_source_t newProcessWatchTimer =
        [ProcessManager createDispatchTimerWithInterval:0.25 * NSEC_PER_SEC
                                                 leeway:(0.25 * NSEC_PER_SEC) / 10
                                          dispatchQueue:dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)
                                          dispatchBlock:^{
            [self processWatcher];
        }];
        _processWatchTimer = newProcessWatchTimer;
    }
}


// Start the process watcher if it's not yet running
- (void)stopProcessWatcher
{
    DDLogDebug(@"%s", __FUNCTION__);
    
    if (_processWatchTimer) {
        dispatch_source_cancel(_processWatchTimer);
        _processWatchTimer = 0;
    }
}


// Start the windows watcher if it's not yet running
- (void)startWindowWatcher
{
    DDLogDebug(@"%s", __FUNCTION__);
    
    if (!_windowWatchTimer) {
        NSDate *dateNextMinute = [NSDate date];
        
        _windowWatchTimer = [[NSTimer alloc] initWithFireDate: dateNextMinute
                                                     interval: 0.25
                                                       target: self
                                                     selector:@selector(windowWatcher)
                                                     userInfo:nil repeats:YES];
        
        NSRunLoop *currentRunLoop = [NSRunLoop currentRunLoop];
        [currentRunLoop addTimer:_windowWatchTimer forMode: NSRunLoopCommonModes];
    }
}


// Start the windows watcher if it's not yet running
- (void)stopWindowWatcher
{
    DDLogDebug(@"%s", __FUNCTION__);
    
    if (_windowWatchTimer) {
        [_windowWatchTimer invalidate];
        _windowWatchTimer = nil;
    }
}


-(void)processWatcher
{
    if (checkingRunningProcesses) {
        DDLogDebug(@"Check for prohibited processes still ongoing, return");
        return;
    }
    checkingRunningProcesses = true;
    
    NSDate *lastTimeProcessCheckBeforeSIGSTOP = lastTimeProcessCheck;
    NSTimeInterval timeSinceLastProcessCheck = [lastTimeProcessCheckBeforeSIGSTOP timeIntervalSinceNow];
    if (!_systemSleeping && detectSIGSTOP && -timeSinceLastProcessCheck > 3 && timeSinceLastProcessCheck <= 0) {
        DDLogError(@"Detected SIGSTOP! SEB was stopped for %f seconds", -timeSinceLastProcessCheck);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!self.SIGSTOPDetected) {
                self.SIGSTOPDetected = YES;
                self->timeProcessCheckBeforeSIGSTOP = lastTimeProcessCheckBeforeSIGSTOP;
                [[NSNotificationCenter defaultCenter]
                 postNotificationName:@"detectedSIGSTOP" object:self];
            }
        });
    }
    
    // Check if not allowed/prohibited processes were activated
    // Get all running processes, including daemons
    NSArray *allRunningProcesses = [self getProcessArray];
    self.runningProcesses = allRunningProcesses;
    NSPredicate *processNameFilter;
    NSArray *filteredProcesses;
    
    // Check for font download process
    if (!_sessionState.allowSwitchToApplications || _isAACEnabled) {
        processNameFilter = [NSPredicate predicateWithFormat:@"name ==[cd] %@ ", fontRegistryUIAgent];
        filteredProcesses = [allRunningProcesses filteredArrayUsingPredicate:processNameFilter];
        if (filteredProcesses.count > 0) {
            if (!fontRegistryUIAgentRunning) {
                fontRegistryUIAgentRunning = YES;
                fontRegistryUIAgentDialogClosed = NO;
                fontRegistryUIAgentSkipDownloadCounter = 20;
            }
            if (fontRegistryUIAgentSkipDownloadCounter > 0 && !fontRegistryUIAgentDialogClosed) {
                
                DDLogWarn(@"%@ is running, and most likely opened dialog to ask user if a font used on the current webpage should be downloaded or skipped. SEB is sending an Event Tap for the key Return (Carriage Return) to close that dialog (invoke default button Skip)", fontRegistryUIAgent);

                if (@available(macOS 10.9, *)) {
                    
                    NSDictionary *options = @{(__bridge id)
                                              kAXTrustedCheckOptionPrompt : @YES};
                    // Check if we're trusted - and the option means "Prompt the user
                    // to trust this app in System Preferences."
                    if (AXIsProcessTrustedWithOptions((CFDictionaryRef)options)) {
                        DDLogDebug(@"SEB is trusted in Privacy / Accessibility");
                        // Now you can use the accessibility APIs
                        DDLogDebug(@"Sending an Event Tap for the key Return (Carriage Return) to close the font donwload dialog (invoking default button Skip)");
                        CGEventPost(kCGSessionEventTap, keyboardEventReturnKey);
                        fontRegistryUIAgentSkipDownloadCounter--;

                    } else {
                        DDLogError(@"SEB is not trusted in Privacy / Accessibility, terminating SEB");
                        
                        // Persist that this event happened and details
                        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
                        [preferences setPersistedSecureBool:YES forKey:fontDownloadAttemptedKey];
                        [preferences setPersistedSecureObject:self.browserController.activeBrowserWindowTitle forKey:fontDownloadAttemptedOnPageTitleKey];
                        [preferences setPersistedSecureObject:[self.browserController placeholderTitleOrURLForActiveWebpage] forKey:fontDownloadAttemptedOnPageURLOrPlaceholderKey];

                        exit(0); //quit SEB
                    }
                } else {
                    // Pre macOS 10.9: Most likely there was no font registry UI agent yet, so this code would be obsolete
                    CGEventPost(kCGSessionEventTap, keyboardEventReturnKey);
                }
                
            } else if (!fontRegistryUIAgentDialogClosed) {
                DDLogError(@"%@ is still running, and the dialog to ask user if a font used on the current webpage should be downloaded or skipped couldn't be closed by SEB. SEB is being force terminated to avoid locking/freezing the Mac completely!", fontRegistryUIAgent);

                exit(0); //quit SEB
            }
        } else {
            if (fontRegistryUIAgentRunning) {
                fontRegistryUIAgentRunning = NO;
                DDLogWarn(@"%@ stopped running", fontRegistryUIAgent);
            }
        }
    }
    // Check for running screen capture process
    if (!allowScreenCapture || _isAACEnabled) {
        NSDictionary *processDetails = nil;
        NSError *error = [self runningProcessCheckForName:screenCaptureAgent inRunningProcesses:&allRunningProcesses processDetails:&processDetails];
        if (processDetails) {
            DDLogDebug(@"Terminating %@ was %@successfull (error: %@)", processDetails, error ? @"not " : @"", error);
        }
    }
    
    if (@available(macOS 13.0, *)) {
        if (!allowDictionaryLookup) {
            NSDictionary *processDetails = nil;
            NSError *error = [self runningProcessCheckForName:lookupQuicklookHelper inRunningProcesses:&allRunningProcesses processDetails:&processDetails];
            if (processDetails) {
                DDLogDebug(@"Lookup is not allowed in settings: Terminating %@ was %@successfull (error: %@)", processDetails, error ? @"not " : @"", error);
                processDetails = nil;
            }

            error = [self runningProcessCheckForName:lookupViewService inRunningProcesses:&allRunningProcesses processDetails:&processDetails];
            if (processDetails) {
                DDLogDebug(@"Lookup is not allowed in settings: Terminating %@ was %@successfull (error: %@)", processDetails, error ? @"not " : @"", error);
            }
        }
    }
    // Kill Passwords menu bar extra if running
    NSDictionary *processDetails = nil;
    NSError *error = [self runningProcessCheckForName:PasswordsMenuBarExtraExecutable inRunningProcesses:&allRunningProcesses processDetails:&processDetails];
    if (processDetails) {
        DDLogDebug(@"Terminating %@ was %@successfull (error: %@)", processDetails, error ? @"not " : @"", error);
    }
    
    if (@available(macOS 15.1, *)) {
        // Kill AI Writing Tools if running
        processDetails = nil;
        error = [self runningProcessCheckForName:WritingToolsExecutable inRunningProcesses:&allRunningProcesses processDetails:&processDetails];
        if (processDetails) {
            DDLogDebug(@"Terminating %@ was %@successfull (error: %@)", processDetails, error ? @"not " : @"", error);
        }
    }
    
    // Check for prohibited BSD processes
    NSArray *prohibitedProcesses = [ProcessManager sharedProcessManager].prohibitedBSDProcesses.copy;
    for (NSString *executableName in prohibitedProcesses) {
        // Wildcards are allowed when filtering process names
        processNameFilter = [NSPredicate predicateWithFormat:@"name LIKE %@", executableName];
        filteredProcesses = [allRunningProcesses filteredArrayUsingPredicate:processNameFilter];
        if (filteredProcesses.count > 0) {
            for (NSDictionary *runningProhibitedProcess in filteredProcesses) {
                NSNumber *PID = [runningProhibitedProcess objectForKey:@"PID"];
                [self killProcessWithPID:PID.intValue];
            }
        }
    }
    
    lastTimeProcessCheck = [NSDate date];
    checkingRunningProcesses = NO;
}

- (NSError *)runningProcessCheckForName:(NSString *)name inRunningProcesses:(NSArray **)allRunningProcesses processDetails:(NSDictionary **)processDetails
{
    // Same swap as containsProcessObject: above, for the same reason — this one runs on the
    // processWatcher's background queue, where the profile showed it was the dominant cost.
    NSArray *filteredProcesses = [*allRunningProcesses containsProcessObject:name];

    NSError *error = nil;
    if (filteredProcesses.count > 0) {
        *processDetails = filteredProcesses[0];
        NSNumber *PID = [*processDetails objectForKey:@"PID"];
        error = [self killProcessWithPID:PID.intValue];
    }
    return error;
}


- (void)windowWatcher
{
    // Check if the font download dialog (if displayed) was successfully closed
    if (fontRegistryUIAgentRunning && !fontRegistryUIAgentDialogClosed) {
        // The dialog was probably displayed and the main thread (and this timer) blocked a while
        // But now the dialog was successfully closed and the main thread is running again
        // stop the process watcher from trying to close the dialog by sending
        // a return key tap
        fontRegistryUIAgentDialogClosed = YES;
        DDLogWarn(@"%@ is still running, but the displayed dialog to ask user if a font used on the current webpage should be downloaded or skipped was most likely closed by SEB.", fontRegistryUIAgent);
    }

    if (checkingForWindows) {
        DDLogDebug(@"Check for prohibited windows still ongoing, returning");
        return;
    }
    checkingForWindows = YES;
    
    if (_isAACEnabled == NO && _wasAACEnabled == NO) {
        CGWindowListOption options;
        BOOL firstScan = NO;
        BOOL fishyWindowWasOpened = NO;
        if (!_systemProcessPIDs) {
            // When this method is called the first time, we scan all windows
            firstScan = YES;
            _systemProcessPIDs = [NSMutableArray new];
            options = kCGWindowListOptionAll;
            fishyWindowWasOpened = YES;

        } else {
            // otherwise only those which are visible (on screen)
            options = kCGWindowListOptionOnScreenOnly; // | kCGWindowListExcludeDesktopElements
        }
        
        NSArray *windowList = CFBridgingRelease(CGWindowListCopyWindowInfo(options, kCGNullWindowID));
        for (NSDictionary *window in windowList) {
            NSString *windowName = [window objectForKey:@"kCGWindowName" ];
            NSString *windowOwner = [window objectForKey:@"kCGWindowOwnerName" ];
    #ifdef DEBUG
            NSString *windowNumber = [window objectForKey:@"kCGWindowNumber" ];
    #endif

            // Close Control Center windows or the Notification Center panel (older macOS versions)
            if ((([windowOwner isEqualToString:@"Notification Center"] && !_sessionState.allowSwitchToApplications) || [windowName isEqualToString:@"NotificationTableWindow"]) &&
                ![_preferencesController preferencesAreOpen]) {
                DDLogWarn(@"Control/Notification Center was opened (owning process name: %@", windowOwner);
                NSArray *notificationCenterSearchResult =[NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.notificationcenterui"];
                if (notificationCenterSearchResult.count > 0) {
                    NSRunningApplication *notificationCenter = notificationCenterSearchResult[0];
                    [notificationCenter forceTerminate];
                }
                continue;
            }
            
            NSString *windowLevelString = [window objectForKey:@"kCGWindowLayer" ];
            NSInteger windowLevel = windowLevelString.integerValue;
            if (windowLevel >= NSMainMenuWindowLevel+2) {
                NSString *windowOwnerPIDString = [window objectForKey:@"kCGWindowOwnerPID"];
                pid_t windowOwnerPID = windowOwnerPIDString.intValue;
                // If this isn't a SEB window
                if (windowOwnerPID != sebPID) {
                    if (![_systemProcessPIDs containsObject:windowOwnerPIDString]) {
                        // If this process isn't in the list of previously scanned and verified
                        // running legit Apple executables
                        NSRunningApplication *appWithPanel = [NSRunningApplication runningApplicationWithProcessIdentifier:windowOwnerPID];
                        NSString *appWithPanelBundleID = appWithPanel.bundleIdentifier;

                        // Blinkered: never terminate the Wacom tablet driver/agent. Students use a
                        // Wacom pen to write maths workings; the driver runs windowless during normal
                        // drawing, but its overlays (radial/on-screen controls, "tablet connected"
                        // notifications, driver-update prompts) ARE windows that would otherwise trip
                        // this anti-overlay scanner and kill the driver mid-session, freezing the pen.
                        // Wacom ships its components under the com.wacom. bundle-ID prefix — allow those
                        // and remember the PID so we don't re-check it every scan.
                        if ([appWithPanelBundleID hasPrefix:@"com.wacom."]) {
                            DDLogWarn(@"Allowing Wacom tablet process %@ (%@) to keep its window — required for pen input.", windowOwner, appWithPanelBundleID);
                            [_systemProcessPIDs addObject:windowOwnerPIDString];
                            continue;
                        }
#ifndef DEBUG
                        DDLogWarn(@"Application %@ with bundle ID %@ has opened a window with level %@", windowOwner, appWithPanelBundleID, windowLevelString);
#endif
    #ifdef DEBUG
                        CGSConnection connection = _CGSDefaultConnection();
                        int workspace;
                        int windowID = windowNumber.intValue;
                        CGSGetWindowWorkspace(connection, windowID, &workspace);
                        DDLogVerbose(@"Window %@ is on space %d", windowName, workspace);
    #endif
                        if (!_sessionState.allowSwitchToApplications && ![_preferencesController preferencesAreOpen]) {
                            if (appWithPanelBundleID && ![appWithPanelBundleID hasPrefix:@"com.apple."]) {
                                // Application hasn't a com.apple. bundle ID prefix
                                // The app which opened the window or panel is no system process
                                if (firstScan) {
                                    DDLogVerbose(@"First scan, don't terminate application %@ (%@)", windowOwner, appWithPanelBundleID);
                                    //[appWithPanel terminate];
                                } else {
                                    DDLogWarn(@"Application %@ is being force terminated because its bundle ID doesn't have the prefix com.apple.", windowOwner);
                                    [self killApplication:appWithPanel];
                                    fishyWindowWasOpened = YES;
                                }
                            } else {
#ifdef DEBUG
                                if ([appWithPanelBundleID isEqualToString:XcodeBundleID]) {
                                    DDLogVerbose(@"Don't terminate application %@ (%@)", windowOwner, appWithPanelBundleID);
                                    [_systemProcessPIDs addObject:windowOwnerPIDString];
                                    continue;
                                }
#else
                                if ([appWithPanelBundleID isEqualToString:FinderBundleID]) {
                                    DDLogWarn(@"Application %@ is being force terminated because it displayed a window in the foreground and this might be used for previewing files!", windowOwner);
                                    [self killProcessWithPID:windowOwnerPID];
                                }
#endif
                                // There is either no bundle ID or the prefix is com.apple.
                                // Check if application with Bundle ID com.apple. is a legit Apple system executable
                                DDLogDebug(@"Check if application %@ (%@) is a signed system executable", windowOwner, appWithPanelBundleID);
                                if ([self signedSystemExecutable:windowOwnerPID]) {
                                    // Cache this executable PID
                                    DDLogDebug(@"Yes, application %@ (%@) is a signed system executable", windowOwner, appWithPanelBundleID);
                                    [_systemProcessPIDs addObject:windowOwnerPIDString];
                                } else {
                                    // The app which opened the window or panel is no system process
                                    if (firstScan) {
                                        DDLogDebug(@"First scan, don't terminate application %@ (%@)", windowOwner, appWithPanelBundleID);
                                        //[appWithPanel terminate];
                                    } else {
                                        DDLogWarn(@"Application %@ is being force terminated because it isn't macOS system software!", windowOwner);
                                        [self killProcessWithPID:windowOwnerPID];
                                        fishyWindowWasOpened = YES;
                                    }
                                }
                            }
                        } else {
#ifndef DEBUG
                            DDLogDebug(@"%@%@don't terminate application %@ (%@)", _sessionState.allowSwitchToApplications ? @"Switching to applications is allowed, " : @"",
                                       _preferencesController.preferencesAreOpen ? @"Preferences are open, " : @"", windowOwner, appWithPanelBundleID);
#endif
                        }
                    }
                }
            }
        }
        if (fishyWindowWasOpened) {
            DDLogVerbose(@"Window list: %@", windowList);
        }
    }
    
    // Check if not allowed/prohibited processes was activated
    // Get all running processes, including daemons
    NSArray *allRunningProcesses = [self.runningProcesses copy];
    
    // Check for activated screen sharing if settings demand it
    if (!_isAACEnabled && _wasAACEnabled == NO && !allowScreenSharing && !self.sessionState.screenSharingCheckOverride &&
        ([allRunningProcesses containsProcessObject:screenSharingAgent] ||
         [allRunningProcesses containsProcessObject:AppleVNCAgent])) {
            [[NSNotificationCenter defaultCenter]
             postNotificationName:@"detectedScreenSharing" object:self];
        }
    
    // Check for activated Siri if settings demand it
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if (!_isAACEnabled && _wasAACEnabled == NO && !_startingUp && !allowSiri && !self.sessionState.siriCheckOverride &&
        [allRunningProcesses containsProcessObject:SiriService] &&
        [[preferences valueForDefaultsDomain:SiriDefaultsDomain key:SiriDefaultsKey] boolValue]) {
            [[NSNotificationCenter defaultCenter]
             postNotificationName:@"detectedSiri" object:self];
        }
    
    // Check for activated dictation if settings demand it
    if (!_isAACEnabled && _wasAACEnabled == NO && !_startingUp && !allowDictation && !self.sessionState.dictationCheckOverride &&
        [allRunningProcesses containsProcessObject:DictationProcess] &&
        ([[preferences valueForDefaultsDomain:DictationDefaultsDomain key:DictationDefaultsKey] boolValue] ||
         [[preferences valueForDefaultsDomain:RemoteDictationDefaultsDomain key:RemoteDictationDefaultsKey] boolValue])) {
            [[NSNotificationCenter defaultCenter]
             postNotificationName:@"detectedDictation" object:self];
        }
    
    checkingForWindows = NO;

    // #100 enforcement check. Deliberately NOT every tick: the watcher runs at 4 Hz because that is
    // how fast a prohibited window must be noticed, but "is my cover on screen" needs its own
    // CGWindowList pass and half a second is ample for a condition that persists until something
    // is done about it. One pass every 8 ticks == 0.5 Hz.
    _blinkeredEnforcementTickCounter += 1;
    if (_blinkeredEnforcementTickCounter % 8 == 0) {
        [self blinkeredEnforcementTick];
    }

    // Kill TouchBar Tool if it's running
    NSArray *runningProcessInstances = [allRunningProcesses containsProcessObject:BTouchBarRestartAgent];
    if (runningProcessInstances.count > 0) {
        [self killProcess:runningProcessInstances[0]];
    }
    runningProcessInstances = [allRunningProcesses containsProcessObject:BTouchBarAgent];
    if (runningProcessInstances.count > 0) {
        [self killProcess:runningProcessInstances[0]];
    }
}


// Get URL (path) to either bundle or executable of a running application
- (NSURL *)getBundleOrExecutableURL:(NSRunningApplication *)runningApp
{
    NSURL *runningAppURL = runningApp.bundleURL;
    if (!runningAppURL) {
        // If this didn't work then it's probably an app without bundle, get executable URL
        runningAppURL = runningApp.executableURL;
    }
    DDLogVerbose(@"NSRunningApplication %@ bundle or executable URL: %@", runningApp, runningAppURL);
    return runningAppURL;
}


// Check if application is a legit Apple system executable
- (BOOL)signedSystemExecutable:(pid_t)runningExecutablePID
{
    NSString * executablePath = [ProcessManager getExecutablePathForPID:runningExecutablePID];
    if (executablePath) {
        NSURL * executableURL = [NSURL fileURLWithPath:executablePath isDirectory:NO];

        DDLogDebug(@"Evaluating code signature of %@", executablePath);
        
        OSStatus status;
        SecStaticCodeRef ref = NULL;
        
        // obtain the cert info from the executable
        status = SecStaticCodeCreateWithPath((__bridge CFURLRef)executableURL, kSecCSDefaultFlags, &ref);
        
        if (ref == NULL) {
            DDLogDebug(@"Couldn't obtain certificate info from executable %@", executablePath);
            return NO;
        }
        if (status != noErr) {
            DDLogDebug(@"Couldn't obtain certificate info from executable %@", executablePath);
            if (ref) {
                CFRelease(ref);
            }
            return NO;
        }
        
        SecRequirementRef req = NULL;
        NSString * reqStr;
        
        if (floor(NSAppKitVersionNumber) >= NSAppKitVersionNumber10_14 ) {
            // Public SHA1 fingerprint of the CA certificate
            // for macOS system software signed by Apple this is the
            // "Software Signing" certificate (use Max Inspect from App Store or similar)
            reqStr = [NSString stringWithFormat:@"%@ %@ = %@%@%@",
                      @"certificate",
                      @"leaf",
                      @"H\"EFDBC9139DD98D",
                      @"BAE5A9C7165A09",
                      @"6511B15EAEF9\""
                      ];
            // create the requirement to check against
            status = SecRequirementCreateWithString((__bridge CFStringRef)reqStr, kSecCSDefaultFlags, &req);
            
            if (status == noErr && req != NULL) {
                status = SecStaticCodeCheckValidity(ref, kSecCSCheckAllArchitectures, req);
                DDLogDebug(@"Returned from checking code signature of executable %@ with status %d", executablePath, (int)status);
            }
        }

        if (status != noErr) {
            if (floor(NSAppKitVersionNumber) >= NSAppKitVersionNumber10_9) {
                // Public SHA1 fingerprint of the CA cert match string
                reqStr = [NSString stringWithFormat:@"%@ %@ = %@%@%@",
                          @"certificate",
                          @"leaf",
                          @"H\"013E2787748A74",
                          @"103D62D2CDBF77",
                          @"A1345517C482\""
                ];
            } else {
                reqStr = [NSString stringWithFormat:@"%@ %@ = %@%@%@",
                          @"certificate",
                          @"leaf",
                          @"H\"2203029E85EFB1",
                          @"828B928C3B6545",
                          @"F003CC0E515C\""
                ];
            }
            
            // create the requirement to check against
            status = SecRequirementCreateWithString((__bridge CFStringRef)reqStr, kSecCSDefaultFlags, &req);
            
            if (status == noErr && req != NULL) {
                status = SecStaticCodeCheckValidity(ref, kSecCSCheckAllArchitectures, req);
                DDLogDebug(@"Returned from checking code signature of executable %@ with status %d", executablePath, (int)status);
            }
        }
        
        if (ref) {
            CFRelease(ref);
        }
        if (req) {
            CFRelease(req);
        }
            
        if (status != noErr) {
            DDLogDebug(@"Code signature suggests that %@ isn't correctly signed macOS system software.", executablePath);
            return NO;
        }

        DDLogDebug(@"Code signature of %@ was checked and it positively identifies macOS system software.", executablePath);
        
        return YES;
    } else {
        DDLogDebug(@"Couldn't determine executable path of process with PID %d.", runningExecutablePID);
        return NO;
    }
}


#pragma mark - Monitoring of Prohibited System Functions

// Switch off display mirroring if it isn't allowed in settings
- (void)conditionallyTerminateDisplayMirroring
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    
    BOOL allowDisplayMirroring = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDisplayMirroring"];
    
    // Also set flags for screen sharing
    allowScreenSharing = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowScreenSharing"] &&
       ![preferences secureBoolForKey:@"org_safeexambrowser_SEB_screenSharingMacEnforceBlocked"];

    // Also set flag for SIGSTOP detection
    detectSIGSTOP = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_detectStoppedProcess"];
    
    // Get list of all displays
    CGDisplayCount maxDisplays = 16;
    CGDirectDisplayID onlineDisplays[maxDisplays];
    CGDisplayCount displayCount = 0;
    CGError error = CGGetOnlineDisplayList(maxDisplays, onlineDisplays, &displayCount);
    if (error != kCGErrorSuccess) {
        DDLogError(@"CGGetOnlineDisplayList error: %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:error userInfo:NULL]);
        return;
    }
    CGDirectDisplayID builtinDisplay = kCGNullDirectDisplay;
    CGDirectDisplayID mainDisplay = kCGNullDirectDisplay;
    BOOL useBuiltin = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowedDisplayBuiltin"];
    BOOL useBuiltinEnforced = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowedDisplayBuiltinEnforce"];
    BOOL useBuiltinEnforcedExceptDesktop = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowedDisplayBuiltinExceptDesktop"];
    BOOL hasBuiltinDisplay = [self.systemManager hasBuiltinDisplay];
    NSUInteger maxAllowedDisplays = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_allowedDisplaysMaxNumber"];
    DDLogInfo(@"Current Settings: Maximum allowed displays: %lu, %suse built-in display.", maxAllowedDisplays, useBuiltin ? "" : "don't ");

    for (int i = 0; i < displayCount; i++)
    {
        CGDirectDisplayID display = onlineDisplays[i];
        CGRect bounds = CGDisplayBounds(display);
        BOOL isBuiltin = CGDisplayIsBuiltin(display);
        BOOL isMain = CGDisplayIsMain(display);
        BOOL isMirrored = CGDisplayIsInMirrorSet(display);
        BOOL isHWMirrored = CGDisplayIsInHWMirrorSet(display);
        BOOL isAlwaysMirrored = CGDisplayIsAlwaysInMirrorSet(display);
        uint32_t vendorID = CGDisplayVendorNumber(display);
        NSString *displayName = [NSScreen displayNameForID:display];
        
        DDLogInfo(@"Display %@ (ID %u) from vendor %u with Resolution %f x %f\n is %sbuilt-in\n is %smain\n is %smirrored\n is %sHW mirrored\n is %salways mirrored",
                  displayName,
                  display,
                  vendorID,
                  bounds.size.width,
                  bounds.size.height,
                  isBuiltin ? "" : "not ",
                  isMain ? "" : "not ",
                  isMirrored ? "" : "not ",
                  isHWMirrored ? "" : "not ",
                  isAlwaysMirrored ? "" : "not ");
        
        if (!_isAACEnabled && !_wasAACEnabled && !allowDisplayMirroring && (isMirrored || isHWMirrored)) {
            CGDisplayConfigRef displayConfigRef;
            
            error = CGBeginDisplayConfiguration(&displayConfigRef);
            if (error != kCGErrorSuccess) {
                DDLogError(@"CGBeginDisplayConfiguration error: %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:error userInfo:NULL]);
                continue;
            }
            
            error = CGConfigureDisplayMirrorOfDisplay(displayConfigRef, display, kCGNullDirectDisplay);
            if (error != kCGErrorSuccess) {
                DDLogError(@"CGConfigureDisplayMirrorOfDisplay error: %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:error userInfo:NULL]);
                continue;
            }
            
            error = CGCompleteDisplayConfiguration(displayConfigRef, kCGConfigureForAppOnly);
            if (error != kCGErrorSuccess) {
                DDLogError(@"CGCompleteDisplayConfiguration error: %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:error userInfo:NULL]);
                continue;
            } else {
                // Switching off mirroring worked, we can abort here
                // and wait for this method to be called again after mirroring is actually off
                return;
            }
        }
        
        // Has the display the built-in flag set?
        if (isBuiltin) {
            DDLogInfo(@"Display %@ (ID %u) is claiming to be built-in", displayName, display);
            // Check if we already found another display which claims (maybe untruthfully) to be built-in
            if (builtinDisplay != kCGNullDirectDisplay) {
                // Another display claimed to be built-in, check if this one has the Apple vendor number
                if (vendorID == 1552) {
                    // This seems to be the real built-in display, rembember it
                    DDLogInfo(@"Display %@ (ID %u) seems to be the real built-in display, as its vendor ID is 1552", displayName, display);
                    builtinDisplay = display;
                }
            } else {
                // this is the first display which claims to be built-in, so save its ID
                builtinDisplay = display;
            }
        }
    }

    NSScreen *mainScreen = nil;
    NSMutableArray *screens = [NSScreen screens].mutableCopy;	// get all available screens
    DDLogDebug(@"All available screens: %@", screens);
    
    // Check if the the built-in display should be the main display according to settings
    self.sessionState.noRequiredBuiltInScreenAvailable = NO;
    if (useBuiltin) {
        DDLogInfo(@"Use built-in option set, using display with ID %u", builtinDisplay);
        // we find the matching main screen
        for (NSUInteger i = 0; i < screens.count; i++)
        {
            NSScreen *iterScreen = screens[i];
            CGDirectDisplayID screenDisplayID = iterScreen.displayID.intValue;
            if (screenDisplayID == builtinDisplay) {
                DDLogInfo(@"Found matching screen (%@) for main display (ID %u)", iterScreen, mainDisplay);
                mainScreen = iterScreen;
                mainScreen.inactive = false;
                [screens removeObjectAtIndex:i];
            }
        }
        if (!mainScreen && ((useBuiltinEnforced && hasBuiltinDisplay) ||
                            (useBuiltinEnforced && !hasBuiltinDisplay && !useBuiltinEnforcedExceptDesktop))) {
            // A built-in display is required, but not available!
            // We still have to find a main display in case of a manual override
            // of the allowedDisplayBuiltinEnforce = true setting
            self.sessionState.noRequiredBuiltInScreenAvailable = YES;
        } else if (mainScreen && self.sessionState.builtinDisplayNotAvailableDetected == YES) {
            // Now there is again a built-in display available
            // lock screen might be closed (if no other lock reason active)
            DDLogInfo(@"Built-in display is again available, lock screen might be closed.");
            [[NSNotificationCenter defaultCenter]
             postNotificationName:@"detectedRequiredBuiltinDisplayMissing" object:self];
        }
    }
    
    // If no main display has been identified, we take the first non-built-in
    if (!mainScreen) {
        for (NSUInteger i = 0; i < screens.count; i++)
        {
            NSScreen *iterScreen = screens[i];
            CGDirectDisplayID screenDisplayID = iterScreen.displayID.intValue;
            if (screenDisplayID != builtinDisplay) {
                DDLogInfo(@"Found matching non built-in screen (%@) for main display", iterScreen);
                mainScreen = iterScreen;
                mainScreen.inactive = false;
                [screens removeObjectAtIndex:i];
                break;
            }
        }
    }
    
    // If we still don't have a screen, then useBuiltin was false and all available screens
    // (probably only one) is built-in, we just take that screen
    if (!mainScreen && screens.count > 0) {
        mainScreen = screens[0];
        mainScreen.inactive = false;
        [screens removeObjectAtIndex:0];
    }
    
    // Flag remaining screens active or inactive
    NSUInteger displaysCounter = (mainScreen != nil);
    for (NSScreen *iterScreen in screens)
    {
        if (displaysCounter < maxAllowedDisplays) {
            iterScreen.inactive = false;
            DDLogInfo(@"Flagged screen %@ as active", iterScreen);
        } else {
            iterScreen.inactive = true;
            DDLogInfo(@"Flagged screen %@ as inactive", iterScreen);
        }
        displaysCounter++;
    }
    
    _mainScreen = mainScreen;
    // Move all browser windows to the previous main screen (if they aren't on it already)
    DDLogInfo(@"Move all browser windows to new main screen %@.", mainScreen);
    [self.browserController moveAllBrowserWindowsToScreen:mainScreen];
    
    if (self.sessionState.noRequiredBuiltInScreenAvailable) {
        [[NSNotificationCenter defaultCenter]
         postNotificationName:@"detectedRequiredBuiltinDisplayMissing" object:self];
    }
}


- (BOOL) noRequiredBuiltInScreenAvailable
{
    DDLogDebug(@"%s %d", __FUNCTION__, self.sessionState.noRequiredBuiltInScreenAvailable);
    return self.sessionState.noRequiredBuiltInScreenAvailable;
}


// Switch off Siri and dictation if not allowed in settings
- (void)conditionallyDisableSpeechInput
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    allowSiri = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowSiri"];
    allowDictation = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDictation"];
    
    // If settings demand it, switch off dictation
    if (allowDictation !=
        ([[preferences valueForDefaultsDomain:DictationDefaultsDomain key:DictationDefaultsKey] boolValue] |
         [[preferences valueForDefaultsDomain:RemoteDictationDefaultsDomain key:RemoteDictationDefaultsKey] boolValue]))
    {
        // We set the master system setting for dictation
        // to the SEB setting value (allow/disallow)
        [preferences setValue:[NSNumber numberWithBool:allowDictation]
                       forKey:DictationDefaultsKey
            forDefaultsDomain:DictationDefaultsDomain];
        
        // If dictation isn't allowed in SEB settings, we switch off
        // remote dictation (running on Apple's servers)
        // We don't change the setting for remote dictation in case
        // SEB settings allow dictation, as the user needs to confirm
        // that audio data is sent to Apple (using system settings
        // before starting SEB)!
        if (allowDictation == NO) {
            [preferences setValue:[NSNumber numberWithBool:NO]
                           forKey:RemoteDictationDefaultsKey
                forDefaultsDomain:RemoteDictationDefaultsDomain];
        }
    }

    // If settings demand it, switch off Siri
    if (allowSiri !=
        [[preferences valueForDefaultsDomain:SiriDefaultsDomain key:SiriDefaultsKey] boolValue]) {
        [preferences setValue:[NSNumber numberWithBool:allowSiri]
                       forKey:SiriDefaultsKey
            forDefaultsDomain:SiriDefaultsDomain];
    }
}


- (void)disableTouchBarFeatures
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];

    // Setting "Touch bar shows = F1, F2, etc. Keys" in System Preferences / Keyboard
    [preferences setValue:TouchBarGlobalDefaultsValue
                   forKey:TouchBarGlobalDefaultsKey
        forDefaultsDomain:TouchBarDefaultsDomain];

    // Setting "Press Fn key to = Show App Controls" in System Preferences / Keyboard
    [preferences setValue:@{TouchBarGlobalDefaultsValue : TouchBarFnDefaultsValue}
                   forKey:TouchBarFnDictionaryDefaultsKey
        forDefaultsDomain:TouchBarDefaultsDomain];

    [self killTouchBarAgent];
}


- (void)killAirPlayUIAgent
{
    NSArray *runningAirPlayAgents = [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.AirPlayUIAgent"];
    if (runningAirPlayAgents.count != 0) {
        for (NSRunningApplication *airPlayAgent in runningAirPlayAgents) {
            DDLogDebug(@"Terminating AirPlayUIAgent %@", airPlayAgent);
            BOOL killSuccess = [airPlayAgent kill];
            DDLogVerbose(@"Success of terminating AirPlayUIAgent: %ld", (long)killSuccess);
        }
    }
}


- (void)killTouchBarAgent
{
    NSArray *runningTouchBarAgents = [NSRunningApplication runningApplicationsWithBundleIdentifier:TouchBarAgent];
    if (runningTouchBarAgents.count != 0) {
        _touchBarDetected = YES;
        for (NSRunningApplication *touchBarAgent in runningTouchBarAgents) {
            DDLogDebug(@"Terminating TouchBarAgent %@", touchBarAgent);
            BOOL killSuccess = [touchBarAgent kill];
            DDLogVerbose(@"Success of terminating TouchBarAgent: %ld", (long)killSuccess);
        }
    }
}


- (void)killScreenCaptureAgent
{
    NSArray *allRunningProcesses = [self getProcessArray];
    NSDictionary *processDetails = nil;
    NSError *error = [self runningProcessCheckForName:screenCaptureAgent inRunningProcesses:&allRunningProcesses processDetails:&processDetails];
    if (processDetails) {
        DDLogDebug(@"Terminating %@ was %@successfull (error: %@)", processDetails, error ? @"not " : @"", error);
    }
}


// Clear Pasteboard, but save the current content in case it is a NSString
- (void)clearPasteboardSavingCurrentString
{
    [self saveCurrentPasteboardString];
    NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
    //NSInteger changeCount = [pasteboard clearContents];
    [pasteboard clearContents];
}

- (void)saveCurrentPasteboardString
{
    NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
    //NSArray *classes = [[NSArray alloc] initWithObjects:[NSString class], [NSAttributedString class], nil];
    NSArray *classes = [[NSArray alloc] initWithObjects:[NSString class], nil];
    NSDictionary *options = [NSDictionary dictionary];
    NSArray *copiedItems = [pasteboard readObjectsForClasses:classes options:options];
    if ((copiedItems != nil) && [copiedItems count]) {
        // if there is a NSSting in the pasteboard, save it for later use
        //[[MyGlobals sharedMyGlobals] setPasteboardString:[copiedItems objectAtIndex:0]];
        [[MyGlobals sharedMyGlobals] setValue:[copiedItems objectAtIndex:0] forKey:@"pasteboardString"];
        DDLogDebug(@"String saved from pasteboard");
    } else {
        [[MyGlobals sharedMyGlobals] setValue:@"" forKey:@"pasteboardString"];
    }
#ifdef DEBUG
    //    NSString *stringFromPasteboard = [[MyGlobals sharedMyGlobals] valueForKey:@"pasteboardString"];
    //    DDLogDebug(@"Saved string from Pasteboard: %@", stringFromPasteboard);
#endif
}


// Clear Pasteboard when quitting/restarting SEB,
// If selected in Preferences, then the current Browser Exam Key is copied to the pasteboard instead
- (void)clearPasteboardCopyingBrowserExamKey
{
    // Clear Pasteboard
    NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
    [pasteboard clearContents];
    
    // Write Browser Exam Key to clipboard if enabled in prefs
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    NSData *hashKey;
    NSMutableArray *pasteboardStrings = NSMutableArray.new;
    BOOL copyBrowserExamKeyToClipboard = [preferences secureBoolForKey:@"org_safeexambrowser_copyBrowserExamKeyToClipboardWhenQuitting"];
    BOOL copyConfigKeyToClipboard = [preferences secureBoolForKey:@"org_safeexambrowser_copyConfigKeyToClipboardWhenQuitting"];
    BOOL moreThanOneKey = copyBrowserExamKeyToClipboard && copyConfigKeyToClipboard;
    if (copyBrowserExamKeyToClipboard) {
        hashKey = self.browserController.browserExamKey;
        [pasteboardStrings addObject:[NSString stringWithFormat:@"%@%@", (moreThanOneKey ? @"Browser Exam Key: " : @""), [hashKey base16String]]];
    }
    if (copyConfigKeyToClipboard) {
        hashKey = self.configKey;
        [pasteboardStrings addObject:[NSString stringWithFormat:@"%@%@", (moreThanOneKey ? @"Config Key: " : @""), [hashKey base16String]]];
    }

    if (pasteboardStrings.count > 0) {
        [pasteboard writeObjects:[NSArray arrayWithObject:[pasteboardStrings componentsJoinedByString:@"\n"]]];
    }
}


#pragma mark - Checks for System Environment

// Check if running on minimal allowed macOS version or a newer version
- (void)checkMinMacOSVersion
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    enforceMinMacOSVersion = NO;
    
    // Check if running on older macOS version than the one allowed in settings
    NSUInteger currentOSMajorVersion = NSProcessInfo.processInfo.operatingSystemVersion.majorVersion;
    NSUInteger currentOSMinorVersion = NSProcessInfo.processInfo.operatingSystemVersion.minorVersion;
    NSUInteger currentOSPatchVersion = NSProcessInfo.processInfo.operatingSystemVersion.patchVersion;

    NSUInteger allowMacOSVersionMajor = SEBMinMacOSVersionSupportedMajor;
    NSUInteger allowMacOSVersionMinor = SEBMinMacOSVersionSupportedMinor;
    NSUInteger allowMacOSVersionPatch = SEBMinMacOSVersionSupportedPatch;

    if (![preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowMacOSVersionNumberCheckFull"]) {
        // Manage old check only for allowed major version
        SEBMinMacOSVersion minMacOSVersion = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_minMacOSVersion"];
        switch (minMacOSVersion) {
            case SEBMinMacOS10_14:
                allowMacOSVersionMajor = 10;
                allowMacOSVersionMinor = 14;
                allowMacOSVersionPatch = 0;
                break;
                
            case SEBMinMacOS10_15:
                allowMacOSVersionMajor = 10;
                allowMacOSVersionMinor = 15;
                allowMacOSVersionPatch = 0;
                break;
                
            case SEBMinMacOS11:
                allowMacOSVersionMajor = 11;
                allowMacOSVersionMinor = 0;
                allowMacOSVersionPatch = 0;
                break;
                
            case SEBMinMacOS12:
                allowMacOSVersionMajor = 12;
                allowMacOSVersionMinor = 0;
                allowMacOSVersionPatch = 0;
                break;
                
            case SEBMinMacOS13:
                allowMacOSVersionMajor = 13;
                allowMacOSVersionMinor = 0;
                allowMacOSVersionPatch = 0;
                break;
                
            case SEBMinMacOS14:
                allowMacOSVersionMajor = 14;
                allowMacOSVersionMinor = 0;
                allowMacOSVersionPatch = 0;
                break;
                
            case SEBMinMacOS15:
                allowMacOSVersionMajor = 15;
                allowMacOSVersionMinor = 0;
                allowMacOSVersionPatch = 0;
                break;
                
            default:
                break;
        }
        DDLogInfo(@"%s: Is running on macOS version with index %lu allowed?", __FUNCTION__, (unsigned long)minMacOSVersion);

    } else {
        // Full granular check for allowed major, minor and patch version
        allowMacOSVersionMajor = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_allowMacOSVersionNumberMajor"];
        allowMacOSVersionMinor = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_allowMacOSVersionNumberMinor"];
        allowMacOSVersionPatch = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_allowMacOSVersionNumberPatch"];
    }
    
    DDLogInfo(@"%s: Is running on macOS version with allow major version %lu, minor version %lu, patch version %lu allowed?", __FUNCTION__, allowMacOSVersionMajor, allowMacOSVersionMinor, allowMacOSVersionPatch);

    // Check for minimal macOS version requirements of this SEB version
    if (allowMacOSVersionMajor < SEBMinMacOSVersionSupportedMajor) {
        allowMacOSVersionMajor = SEBMinMacOSVersionSupportedMajor;
        allowMacOSVersionMinor = SEBMinMacOSVersionSupportedMinor;
        allowMacOSVersionPatch = SEBMinMacOSVersionSupportedPatch;
    } else if (allowMacOSVersionMajor == SEBMinMacOSVersionSupportedMajor) {
        if (allowMacOSVersionMinor < SEBMinMacOSVersionSupportedMinor) {
            allowMacOSVersionMinor = SEBMinMacOSVersionSupportedMinor;
            allowMacOSVersionPatch = SEBMinMacOSVersionSupportedPatch;
        } else if (allowMacOSVersionMinor == SEBMinMacOSVersionSupportedMinor && allowMacOSVersionPatch < SEBMinMacOSVersionSupportedPatch) {
            allowMacOSVersionPatch = SEBMinMacOSVersionSupportedPatch;
        }
    }

    if (currentOSMajorVersion < allowMacOSVersionMajor ||
        (currentOSMajorVersion == allowMacOSVersionMajor &&
         currentOSMinorVersion < allowMacOSVersionMinor) ||
        (currentOSMajorVersion == allowMacOSVersionMajor &&
         currentOSMinorVersion == allowMacOSVersionMinor &&
         currentOSPatchVersion < allowMacOSVersionPatch)
        )
    {
        NSString *allowedMacOSVersionMinorString = @"";
        NSString *allowedMacOSVersionPatchString = @"";
        if (allowMacOSVersionPatch > 0 || allowMacOSVersionMinor > 0) {
            allowedMacOSVersionMinorString = [NSString stringWithFormat:@".%lu", (unsigned long)allowMacOSVersionMinor];
        }
        if (allowMacOSVersionPatch > 0) {
            allowedMacOSVersionPatchString = [NSString stringWithFormat:@".%lu", (unsigned long)allowMacOSVersionPatch];
        }
        NSString *alertMessageMacOSVersion = [NSString stringWithFormat:@"%@%@%lu%@%@",
                                            SEBShortAppName,
                                            NSLocalizedString(@" settings don't allow to run on the macOS version installed on this device. Update to latest macOS version or at least macOS ", @""),
                                            (unsigned long)allowMacOSVersionMajor,
                                            allowedMacOSVersionMinorString,
                                            allowedMacOSVersionPatchString];
        DDLogError(@"%s %@", __FUNCTION__, alertMessageMacOSVersion);
        
        NSAlert *modalAlert = [self newAlert];
        [modalAlert setMessageText:[NSString stringWithFormat:NSLocalizedString(@"Running on Current macOS Version Not Allowed!", @"")]];
        [modalAlert setInformativeText:alertMessageMacOSVersion];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
        [modalAlert setAlertStyle:NSAlertStyleCritical];
        void (^terminateSEBAlertOK)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self removeAlertWindow:modalAlert.window];
            self->enforceMinMacOSVersion = YES;
            if (self.startingUp) {
                [self requestedExit:nil]; // Quit SEB
            } else {
                [self quitSEBOrSession];
            }
        };
        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))terminateSEBAlertOK];
    } else {
        DDLogInfo(@"%s: Running on current macOS version is allowed.", __FUNCTION__);
    }
}


// Check if SEB is placed ("installed") in an Applications folder
- (BOOL)installedInApplicationsFolder
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    NSString *currentSEBBundlePath =[[NSBundle mainBundle] bundlePath];
    BOOL installedInApplicationsFolder = false;
    DDLogDebug(@"SEB was started up from this path: %@", currentSEBBundlePath);
    if (![self isInApplicationsFolder:currentSEBBundlePath]) {
        // Has SEB to be installed in an Applications folder?
        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_forceAppFolderInstall"]) {
#ifndef DEBUG
            DDLogError(@"Current settings require SEB to be installed in an Applications folder, but it isn't! SEB will therefore quit!");
            _forceAppFolder = YES;
            [self quitSEBOrSession]; // Quit SEB or the exam session
#else
            DDLogDebug(@"Current settings require SEB to be installed in an Applications folder, but it isn't! SEB would quit if not Debug build.");
#endif
        }
    } else {
        DDLogInfo(@"SEB was started up from an Applications folder.");
        installedInApplicationsFolder = true;
    }
    return installedInApplicationsFolder;
}


- (BOOL) isInApplicationsFolder:(NSString *)path
{
    NSArray *applicationDirs;
    if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_allowUserAppFolderInstall"]) {
        // Allow also user's ~/Applications directories
        applicationDirs = NSSearchPathForDirectoriesInDomains(NSApplicationDirectory,
                                                              NSLocalDomainMask | NSUserDomainMask,
                                                              YES);
    } else {
        applicationDirs = NSSearchPathForDirectoriesInDomains(NSApplicationDirectory,
                                                              NSLocalDomainMask,
                                                              YES);
    }
    for (NSString *appDir in applicationDirs) {
        if ([path hasPrefix:appDir]) return YES;
    }
    return NO;
}


// Check for command key being held down
- (BOOL)alternateKeyCheck
{
    NSEventModifierFlags modifierFlags = [NSEvent modifierFlags];
    BOOL altKeyDown = (0 != (modifierFlags & NSEventModifierFlagOption));
    return (altKeyDown && [[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_allowPreferencesWindow"]);
}


// Check for command key being held down
- (void)appSwitcherCheck
{
    NSEventModifierFlags modifierFlags = [NSEvent modifierFlags];
    BOOL commandKeyHeld = (0 != (modifierFlags & NSEventModifierFlagCommand));
    if (!commandKeyHeld) {
        return;
    }
    // [Blinkered] _cmdKeyDown IS THE ALERT'S TRIGGER, NOT A DIAGNOSTIC — set it only when the
    // check is actually enabled.
    //
    // It used to be assigned unconditionally, one line above the setting that gates everything
    // else here. That is a real defect and not a tidiness point: the flag survives for the whole
    // session, and applicationWillTerminate's `else if (_cmdKeyDown)` branch raises
    // "Holding Command Key Not Allowed! … Restart Blinkered without holding any keys."
    // Because it is raised at TERMINATION, the parent sees it AFTER a successful unlock, on the
    // desktop, about a key they pressed and released minutes earlier — and its OK button is what
    // applicationWillTerminateProceed waits on, so teardown wedges until the 3 s POST-SAVE
    // watchdog forces the exit.
    //
    // Observed on Maggie B's kids Mac, 21 Aug 2026, with enableAppSwitcherCheck already false:
    //   07:09:52.633  Command key is pressed, but not forbidden in current settings   (lock held)
    //   07:10:12.688  -[SEBController exitSEB]                                        (the unlock)
    //   07:10:12.731  Adding modal alert window <_NSAlertPanel>                       (this alert)
    //   07:10:15.814  teardown watchdog: POST-SAVE fired (3s) — quit wedged after the save
    // Photographed on screen with the Dock and menu bar visible — i.e. the device was unlocked and
    // working when it told the parent to restart it.
    //
    // blinkered-classroom now ships enableAppSwitcherCheck=false in every .seb (PR #739), which
    // stops the QUIT — a confirmed credential-free lock bypass. It cannot stop this flag, so the
    // alert is the visible remnant of a defect that is otherwise closed.
    if (![[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_enableAppSwitcherCheck"]) {
        DDLogWarn(@"Command key is pressed, but not forbidden in current settings");
        return;   // deliberately WITHOUT setting _cmdKeyDown — see above
    }
    _cmdKeyDown = YES;
    DDLogError(@"Command key is pressed and forbidden, SEB cannot continue");
    [self requestedExit:nil]; // Quit SEB
}


// Check if the Force Quit window is open
- (BOOL)forceQuitWindowCheckContinue
{
    while ([self forceQuitWindowOpen]) {
        // Show alert that the Force Quit window is open
        DDLogError(@"Force Quit window is open!");
            DDLogError(@"Show error message and ask user to close it or quit SEB.");
            NSAlert *modalAlert = [self newAlert];
            [modalAlert setMessageText:NSLocalizedString(@"Close Force Quit Window", @"")];
        [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"%@ cannot run when the Force Quit window or another system frontmost dialog is open. Close the window or quit %@. If the window isn't open and this alert is displayed anyways, restart your Mac.", @""), SEBShortAppName, SEBShortAppName]];
            [modalAlert setAlertStyle:NSAlertStyleCritical];
            [modalAlert addButtonWithTitle:NSLocalizedString(@"Retry", @"")];
            [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
            NSInteger answer = [modalAlert runModal];
            [self removeAlertWindow:modalAlert.window];
            switch(answer)
            {
                case NSAlertFirstButtonReturn:
                    DDLogError(@"Force Quit window was open, user clicked retry");
                    break; // Test if window is closed now
                    
                case NSAlertSecondButtonReturn:
                {
                    // Quit SEB
                    DDLogError(@"Force Quit window was open, user decided to quit SEB.");
                    [self requestedExit:nil]; // Quit SEB
                    return NO;
                }
            }
    }
    return YES;
}


// Check if the Force Quit window is open
// YES while the macOS login/unlock screen is up (screen locked, or the session
// isn't the one on the console — e.g. woken from sleep and not yet unlocked, or
// fast-user-switched away). In that state loginwindow owns a legitimate full-size
// window that is the LOCK SCREEN, not a Force Quit dialog.
- (BOOL)blinkeredScreenIsLocked
{
    CFDictionaryRef sessionInfo = CGSessionCopyCurrentDictionary();
    if (!sessionInfo) {
        return NO;
    }
    BOOL locked = NO;
    CFBooleanRef isLocked = CFDictionaryGetValue(sessionInfo, CFSTR("CGSSessionScreenIsLocked"));
    if (isLocked && CFBooleanGetValue(isLocked)) {
        locked = YES;
    }
    CFBooleanRef onConsole = CFDictionaryGetValue(sessionInfo, kCGSessionOnConsoleKey);
    if (onConsole && !CFBooleanGetValue(onConsole)) {
        locked = YES;
    }
    CFRelease(sessionInfo);
    return locked;
}

- (BOOL)forceQuitWindowOpen
{
    // While the login/unlock screen is up (e.g. the agent relaunched Blinkered to
    // lock a device that was asleep, and the user hasn't authenticated yet), the
    // fullscreen loginwindow window is the LOCK SCREEN — not a Force Quit dialog,
    // which can't be open while locked. Don't block: let the lockdown proceed
    // behind the login screen so the user unlocks straight into Blinkered.
    if ([self blinkeredScreenIsLocked]) {
        DDLogInfo(@"Screen is locked (login/unlock screen up) — not treating loginwindow as the Force Quit window; proceeding with lockdown");
        return NO;
    }
    BOOL forceQuitWindowOpen = false;
    NSInteger phantomLoginwindowWindows = 0;
    NSArray *windowList = CFBridgingRelease(CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID));
    for (NSDictionary *windowInformation in windowList) {
        if ([[windowInformation valueForKey:@"kCGWindowOwnerName"] isEqualToString:@"loginwindow"]) {
            // macOS 26 keeps permanent zero-sized loginwindow windows on screen at a
            // negative window level; treating those as "Force Quit window is open"
            // blocked every session launch. The real Force Quit panel (and any other
            // frontmost loginwindow dialog) has a non-trivial size and a level >= 0.
            NSNumber *layer = [windowInformation valueForKey:@"kCGWindowLayer"];
            if (layer && layer.integerValue < 0) {
                phantomLoginwindowWindows++;
                continue;
            }
            CGRect bounds = CGRectZero;
            CFDictionaryRef boundsDict = (__bridge CFDictionaryRef)[windowInformation valueForKey:@"kCGWindowBounds"];
            if (boundsDict && CGRectMakeWithDictionaryRepresentation(boundsDict, &bounds) &&
                (bounds.size.width <= 1 || bounds.size.height <= 1)) {
                phantomLoginwindowWindows++;
                continue;
            }
            forceQuitWindowOpen = true;
            break;
        }
    }
    if (phantomLoginwindowWindows > 0) {
        DDLogWarn(@"Ignored %ld phantom (zero-sized or sub-desktop-level) loginwindow window(s) while checking for the Force Quit window — pre-3.6.100 builds would have refused to start this session", (long)phantomLoginwindowWindows);
    }
    return forceQuitWindowOpen;
}


#pragma mark - System Lock Down Functionalities

static bool _systemSleeping;

// Method called by I/O Kit power management
void MySleepCallBack( void * refCon, io_service_t service, natural_t messageType, void * messageArgument )
{
    DDLogDebug(@"messageType %08lx, arg %08lx\n",
		   (long unsigned int)messageType,
		   (long unsigned int)messageArgument );
	
    switch ( messageType )
    {
			
        case kIOMessageCanSystemSleep:
            /* Idle sleep is about to kick in. This message will not be sent for forced sleep.
			 Applications have a chance to prevent sleep by calling IOCancelPowerChange.
			 Most applications should not prevent idle sleep.
			 
			 Power Management waits up to 30 seconds for you to either allow or deny idle sleep.
			 If you don't acknowledge this power change by calling either IOAllowPowerChange
			 or IOCancelPowerChange, the system will wait 30 seconds then go to sleep.
			 */
			
            // Blinkered: ALLOW idle sleep during a lock. SEB cancels idle sleep so an EXAM screen stays
            // visible to a proctor, but for a home all-day lockdown that just drains the battery and makes
            // an idle, screen-off Mac read "Online" on the parent dashboard (it's awake, still polling).
            // A locked Mac that idle-sleeps re-locks the moment it wakes (persisted lock + agent
            // poll-on-wake), so sleeping never weakens the lock, and the agent's sleep beacon then surfaces
            // it as "Sleeping". (Forced sleep, e.g. lid close, was never cancellable here anyway.)
            DDLogDebug(@"kIOMessageCanSystemSleep: IOAllowPowerChange (home lockdown allows idle sleep)");
            IOAllowPowerChange( root_port, (long)messageArgument );
            break;
			
        case kIOMessageSystemWillSleep:
            /* The system WILL go to sleep. If you do not call IOAllowPowerChange or
			 IOCancelPowerChange to acknowledge this message, sleep will be
			 delayed by 30 seconds.
			 
			 NOTE: If you call IOCancelPowerChange to deny sleep it returns kIOReturnSuccess,
			 however the system WILL still go to sleep. 
			 */
            DDLogDebug(@"kIOMessageSystemWillSleep");
            _systemSleeping = true;

			//IOCancelPowerChange( root_port, (long)messageArgument );
			//IOAllowPowerChange( root_port, (long)messageArgument );
            break;
			
        case kIOMessageSystemWillPowerOn:
            //System has started the wake up process...
            DDLogDebug(@"kIOMessageSystemWillPowerOn");
            break;
			
        case kIOMessageSystemHasPoweredOn:
            //System has finished waking up...
            DDLogDebug(@"kIOMessageSystemHasPoweredOn");
            _systemSleeping = false;
			break;
			
        default:
            break;
			
    }
}


bool insideMatrix(void){
	unsigned char mem[4] = {0,0,0,0};
	//__asm ("str mem");
	if ( (mem[0]==0x00) && (mem[1]==0x40))
		return true; //printf("INSIDE MATRIX!!\n");
	else
		return false; //printf("OUTSIDE MATRIX!!\n");
	return false;
}


// Close the About Window
- (void) closeAboutWindow {
    DDLogInfo(@"Attempting to close About SEB window %@", self.aboutWindow);
    [self.aboutWindow orderOut:self];
}


// Open background windows on all available screens to prevent Finder becoming active when clicking on the desktop background
#pragma mark - Blinkered: foreign full-screen Space (the #100 lock bypass)

// macOS gives a natively full-screened app its OWN Space, and a cover window created while such a
// Space is current is associated with the OTHER Space — so it never appears. The kiosk then covers
// nothing while sitting there frontmost, owning the menu bar, and reporting itself locked.
// Device-confirmed on macOS 26.5.2 with Safari left in full screen: Blinkered frontmost, its cover
// at 0.00 coverage, the child browsing freely, and the dashboard showing "Locked".
// Full evidence: docs/KIOSK_FULLSCREEN_SPACE_INVESTIGATION.md.
//
// WHY THE KIOSK NEVER NOTICED. Two independent gaps, both closed here:
//   • -spaceSwitch: is gated on `launchedApplication`, i.e. an app that launched AFTER SEB started.
//     An app ALREADY in full screen when the lock begins raises no launch notification and no Space
//     CHANGE, so it matched nothing.
//   • -windowWatcher sees the full-screen app's level-26 menu strip, but a signed com.apple. app
//     passing -signedSystemExecutable: is cached in _systemProcessPIDs and never looked at again.
//     Safari in full screen is therefore detected and then permanently exempted — which is exactly
//     why Safari keeps browsing while an unsigned app in the same state gets killed.
//
// WHAT WAS TRIED AND DOES NOT WORK — all measured on the device, recorded so nobody re-litigates:
//   • NSRunningApplication.hide()  — returns NO. macOS refuses to hide a full-screen app.
//   • hideOtherApplications()      — already called from -regainActiveStatus: on every cycle, and
//                                    the bypass persists straight through it.
//   • terminating the app          — INSUFFICIENT, and the most important negative result: the
//                                    Space OUTLIVES the app, orphaned and empty, and the kiosk is
//                                    still on the wrong one. Killing buys nothing here.
//
// WHAT DOES WORK: switch the display back to an ordinary Space BEFORE the covers are raised. The
// covers then associate correctly and — verified on the device — stay on top even when the
// full-screen Space is made current again afterwards. So this is an ORDERING bug, not an
// impossibility: no app is killed, no Space destroyed, nothing of the child's lost.

static const int kBlinkeredCGSSpaceTypeFullScreen = 4;      // CGS space "type" (0 = ordinary user Space)
static const NSTimeInterval kBlinkeredSpaceRemedyMinInterval = 2.0;   // never fight the OS or the child faster than this

typedef int32_t BlinkeredCGSConnection;
typedef BlinkeredCGSConnection (*BlinkeredCGSMainConnectionIDFn)(void);
typedef CFArrayRef (*BlinkeredCGSCopyManagedDisplaySpacesFn)(BlinkeredCGSConnection);
typedef int32_t (*BlinkeredCGSManagedDisplaySetCurrentSpaceFn)(BlinkeredCGSConnection, CFStringRef, uint64_t);

typedef struct {
    BOOL resolved;
    BlinkeredCGSMainConnectionIDFn mainConnectionID;
    BlinkeredCGSCopyManagedDisplaySpacesFn copyManagedDisplaySpaces;
    BlinkeredCGSManagedDisplaySetCurrentSpaceFn setCurrentSpace;
} BlinkeredCGSSymbols;

// Resolved by dlsym rather than linked, deliberately: these are PRIVATE, unsupported SkyLight
// symbols. Linking them would make the app fail to launch the day Apple removes one; resolving them
// means we simply lose the Space remedy and say so. Resolved once per process.
static BlinkeredCGSSymbols blinkeredCGS(void)
{
    static BlinkeredCGSSymbols syms;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void *handle = dlopen("/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight", RTLD_LAZY);
        if (!handle) {
            DDLogError(@"Blinkered: SkyLight unavailable — the full-screen Space remedy is disabled for this process");
            return;
        }
        syms.mainConnectionID = (BlinkeredCGSMainConnectionIDFn)dlsym(handle, "CGSMainConnectionID");
        syms.copyManagedDisplaySpaces = (BlinkeredCGSCopyManagedDisplaySpacesFn)dlsym(handle, "CGSCopyManagedDisplaySpaces");
        syms.setCurrentSpace = (BlinkeredCGSManagedDisplaySetCurrentSpaceFn)dlsym(handle, "CGSManagedDisplaySetCurrentSpace");
        syms.resolved = (syms.mainConnectionID != NULL
                         && syms.copyManagedDisplaySpaces != NULL
                         && syms.setCurrentSpace != NULL);
        if (!syms.resolved) {
            DDLogError(@"Blinkered: CGS Space symbols missing (main=%d copy=%d set=%d) — Space remedy disabled",
                       syms.mainConnectionID != NULL, syms.copyManagedDisplaySpaces != NULL, syms.setCurrentSpace != NULL);
        }
    });
    return syms;
}

typedef NS_ENUM(NSInteger, BlinkeredSpaceState) {
    // UNKNOWN IS NOT "FINE". The whole Space module rides unsupported private API; the day it goes
    // away this must degrade to "I cannot tell", never to "verified OK". Every caller treats
    // Unknown as "no remedy available" and the enforcement verdict falls back to the GEOMETRIC
    // test, which needs no private API at all.
    BlinkeredSpaceStateUnknown = 0,
    BlinkeredSpaceStateOrdinary,
    BlinkeredSpaceStateFullScreen,
};

// Reports whether ANY display currently shows a full-screen Space, and if so which display it is
// and an ordinary Space on that display to switch back to.
static BlinkeredSpaceState blinkeredCurrentSpaceState(NSString **fullScreenDisplayOut, uint64_t *ordinarySpaceOut)
{
    BlinkeredCGSSymbols syms = blinkeredCGS();
    if (!syms.resolved) {
        return BlinkeredSpaceStateUnknown;
    }
    CFArrayRef displaysRef = syms.copyManagedDisplaySpaces(syms.mainConnectionID());
    if (!displaysRef) {
        return BlinkeredSpaceStateUnknown;
    }
    NSArray *displays = CFBridgingRelease(displaysRef);
    BlinkeredSpaceState state = BlinkeredSpaceStateOrdinary;
    for (id displayEntry in displays) {
        if (![displayEntry isKindOfClass:[NSDictionary class]]) {
            continue;
        }
        NSDictionary *display = displayEntry;
        NSDictionary *currentSpace = display[@"Current Space"];
        NSArray *spaces = display[@"Spaces"];
        if (![currentSpace isKindOfClass:[NSDictionary class]] || ![spaces isKindOfClass:[NSArray class]]) {
            continue;
        }
        if ([currentSpace[@"type"] intValue] != kBlinkeredCGSSpaceTypeFullScreen) {
            continue;
        }
        // This display is showing a full-screen Space. Find an ordinary one to go back to; if the
        // display has none (every Space on it is full-screen) there is nothing to switch to and we
        // must not pretend otherwise.
        for (id spaceEntry in spaces) {
            if (![spaceEntry isKindOfClass:[NSDictionary class]]) {
                continue;
            }
            NSDictionary *space = spaceEntry;
            if ([space[@"type"] intValue] == kBlinkeredCGSSpaceTypeFullScreen) {
                continue;
            }
            NSString *identifier = display[@"Display Identifier"];
            if (![identifier isKindOfClass:[NSString class]]) {
                continue;
            }
            if (fullScreenDisplayOut) { *fullScreenDisplayOut = identifier; }
            if (ordinarySpaceOut) { *ordinarySpaceOut = [space[@"ManagedSpaceID"] unsignedLongLongValue]; }
            return BlinkeredSpaceStateFullScreen;
        }
        state = BlinkeredSpaceStateFullScreen;   // full-screen, but nowhere to switch to
    }
    return state;
}

static BOOL blinkeredSwitchDisplayToSpace(NSString *displayIdentifier, uint64_t spaceID)
{
    BlinkeredCGSSymbols syms = blinkeredCGS();
    if (!syms.resolved || displayIdentifier.length == 0 || spaceID == 0) {
        return NO;
    }
    int32_t err = syms.setCurrentSpace(syms.mainConnectionID(), (__bridge CFStringRef)displayIdentifier, spaceID);
    return err == 0;
}


// Is the kiosk supposed to own the whole screen right now? Everything in this module is a no-op
// when it is not — during teardown, under AAC (which manages its own containment), and whenever
// the config allows switching to other apps, where a full-screen app is legitimate and fighting it
// would be a bug rather than a fix.
- (BOOL)blinkeredKioskShouldOwnScreen
{
    if (_blinkeredTeardownStarted || _isTerminating || self.settingsOpen) {
        return NO;
    }
    if (_isAACEnabled || _wasAACEnabled) {
        return NO;
    }
    if (_sessionState.allowSwitchToApplications) {
        return NO;
    }
    // THE EARLY-STARTUP WINDOW IS THE ONE THAT MATTERS, so it is checked FIRST. While the
    // session-launch covers are up, settings have not been applied yet and elevateWindowLevels
    // still reads NO — but -coverScreens elevates the covers anyway (same condition). That window
    // is precisely when the covers are first CREATED, i.e. when being on the wrong Space does the
    // damage, so gating this module on the preference alone would have skipped the only pass that
    // could have prevented the bypass.
    if (_blinkeredEarlyCoversActive && _startingUp) {
        return YES;
    }
    // Otherwise: elevateWindowLevels YES == "third-party apps are NOT allowed", i.e. the covers are
    // elevated and the kiosk owns the screen. Same read -regainActiveStatus: and -coverScreens use,
    // kept in that form so the three cannot drift apart.
    return [[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_elevateWindowLevels"];
}

// THE FIX. If the display is showing someone else's full-screen Space, switch back to an ordinary
// one and re-raise the covers there. Rate-limited so it can never become a ping-pong with a
// determined child or with the window server, and re-entrancy-guarded because -coverScreens calls
// this on the way in and this calls -coverScreens on the way out.
- (BOOL)blinkeredEnsureOrdinarySpace:(NSString *)reason
{
    if (_blinkeredInSpaceRemedy || ![self blinkeredKioskShouldOwnScreen]) {
        return NO;
    }
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    if (now - _blinkeredLastSpaceRemedyAt < kBlinkeredSpaceRemedyMinInterval) {
        return NO;
    }
    NSString *display = nil;
    uint64_t ordinarySpace = 0;
    BlinkeredSpaceState state = blinkeredCurrentSpaceState(&display, &ordinarySpace);
    if (state != BlinkeredSpaceStateFullScreen) {
        return NO;     // ordinary Space, or CGS unavailable — nothing this path can do
    }
    if (display.length == 0 || ordinarySpace == 0) {
        DDLogError(@"Blinkered: a full-screen Space is current (%@) but there is no ordinary Space to switch to — the kiosk cannot take the screen", reason);
        return NO;
    }
    _blinkeredLastSpaceRemedyAt = now;
    _blinkeredInSpaceRemedy = YES;
    BOOL switched = blinkeredSwitchDisplayToSpace(display, ordinarySpace);
    DDLogWarn(@"Blinkered: foreign full-screen Space was current (%@) — switching display %@ to ordinary Space %llu: %@",
              reason, display, (unsigned long long)ordinarySpace, switched ? @"OK" : @"FAILED");
    if (switched) {
        // Raising the covers is the half that actually matters: the switch alone only changes which
        // Space is on screen, and the covers still have to be re-associated with it. This mirrors
        // what -regainActiveStatus: does, and it is what was observed to make the covers stick.
        [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
        [self coverScreens];
        if (self.browserController.mainBrowserWindow.isVisible) {
            [self.browserController.mainBrowserWindow makeKeyAndOrderFront:self];
        }
    }
    _blinkeredInSpaceRemedy = NO;
    return switched;
}

// Is the macOS login window / screen saver currently covering everything? If so there is NO
// VERDICT TO GIVE. The OS lock screen sits ABOVE the kiosk cover, which is strictly MORE secure,
// not less — but geometrically it looks exactly like something obscuring us.
//
// Found on the device: the first build of this reported
//   "NOT ENFORCING (obscured-by-loginwindow) — the kiosk is not covering the screen"
// the moment the Mac's screen locked. Left in, that would have raised a "your device is not
// actually locked" alert at every screen lock on every device — turning the one signal that is
// supposed to mean a real bypass into routine noise, which is worse than not having it.
static BOOL blinkeredScreenIsLockedOrSaverActive(void)
{
    CFDictionaryRef sessionRef = CGSessionCopyCurrentDictionary();
    if (!sessionRef) {
        return NO;
    }
    NSDictionary *session = CFBridgingRelease(sessionRef);
    // Both keys are absent on a normal unlocked console session.
    BOOL locked = [session[@"CGSSessionScreenIsLocked"] boolValue];
    BOOL onConsole = session[@"kCGSSessionOnConsoleKey"] == nil
                     || [session[@"kCGSSessionOnConsoleKey"] boolValue];
    return locked || !onConsole;
}

// Window owners that are macOS CHROME, not "an app on screen". Excluding them is what lets the
// verdict be geometric at all — the Dock draws the wallpaper as a full-screen window, the window
// server draws the menu-bar strip, and loginwindow / the screen saver / SecurityAgent legitimately
// draw ABOVE everything including a kiosk.
//
// SPOOFING, and why it is bounded: kCGWindowOwnerName comes from the process itself, so an app
// could in principle name itself "Dock" to be skipped here. The bundle-identifier check makes that
// harder, and the consequence is bounded anyway — this list only affects the REPORT. It cannot
// weaken the enforcement itself: the Space remedy and the cover levels do not consult it, and
// -windowWatcher independently force-terminates any non-Apple app that opens a window at the
// kiosk's level. A process that fails to resolve is treated as NOT chrome, i.e. as blocking.
static BOOL blinkeredWindowOwnerIsSystemChrome(NSString *ownerName, pid_t ownerPID)
{
    static NSSet *chromeNames;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        chromeNames = [NSSet setWithArray:@[@"Window Server", @"Dock", @"loginwindow",
                                            @"ScreenSaverEngine", @"SecurityAgent",
                                            @"Control Centre", @"Control Center",
                                            @"Notification Centre", @"Notification Center",
                                            @"SystemUIServer", @"Spotlight", @"WindowManager"]];
    });
    if (![chromeNames containsObject:ownerName]) {
        return NO;
    }
    NSRunningApplication *owner = [NSRunningApplication runningApplicationWithProcessIdentifier:ownerPID];
    NSString *bundleID = owner.bundleIdentifier;
    // "Window Server" and "Dock" have no resolvable NSRunningApplication in some states; they are
    // the two that predate this list and are known-safe by their level (24 / 20 wallpaper).
    if (bundleID == nil) {
        return [ownerName isEqualToString:@"Window Server"] || [ownerName isEqualToString:@"Dock"];
    }
    return [bundleID hasPrefix:@"com.apple."];
}

// THE VERDICT — "is my cover actually the thing on screen?", answered GEOMETRICALLY.
//
// Deliberately NOT derived from isActive / frontmost / ownsMenuBar. During the bypass all three
// report success: Blinkered IS frontmost and DOES own the menu bar while covering nothing, which is
// precisely how a launch came to be reported as an enforced lock. The only honest question is
// whether our window is the one the child is looking at.
//
// This uses no private API. It is the fallback that keeps working if the CGS symbols above ever
// disappear; CGS only sharpens the REASON string.
//
// Returns nil when no verdict should be reported at all (kiosk not meant to own the screen).
- (NSDictionary *)blinkeredComputeEnforcementVerdict
{
    if (![self blinkeredKioskShouldOwnScreen]) {
        return nil;
    }
    if (blinkeredScreenIsLockedOrSaverActive()) {
        return nil;    // the OS is covering the screen for us — no verdict to give (see above)
    }
    NSScreen *screen = NSScreen.screens.firstObject;
    CGFloat screenArea = screen.frame.size.width * screen.frame.size.height;
    if (screenArea <= 0) {
        return nil;
    }
    NSArray *windowList = CFBridgingRelease(CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements, kCGNullWindowID));
    BOOL covered = NO;
    NSString *blockedBy = nil;
    // Front-to-back. The first thing we meet decides it: our own full-screen cover means the screen
    // is ours; another app's substantial window first means it is not.
    for (NSDictionary *window in windowList) {
        NSInteger layer = [window[(id)kCGWindowLayer] integerValue];
        if (layer < 0) {
            continue;    // drawn below the desktop content (widgets etc.) — never covers anything
        }
        CGRect bounds = CGRectZero;
        if (!CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)window[(id)kCGWindowBounds], &bounds)) {
            continue;
        }
        double fraction = (bounds.size.width * bounds.size.height) / screenArea;
        pid_t ownerPID = (pid_t)[window[(id)kCGWindowOwnerPID] intValue];
        if (ownerPID == sebPID) {
            if (fraction >= 0.95) {
                covered = YES;
                break;
            }
            continue;    // one of our smaller windows (dock, shield) — keep looking for the cover
        }
        NSString *owner = window[(id)kCGWindowOwnerName] ?: @"";
        if (blinkeredWindowOwnerIsSystemChrome(owner, ownerPID)) {
            continue;
        }
        if (fraction >= 0.02) {
            blockedBy = owner;
            break;
        }
    }
    if (covered) {
        return @{ @"ok": @YES };
    }
    NSString *reason;
    if (blinkeredCurrentSpaceState(NULL, NULL) == BlinkeredSpaceStateFullScreen) {
        reason = @"foreign-fullscreen-space";
    } else if (blockedBy.length > 0) {
        // The owner name is another app's, so it is untrusted text on its way to a parent-facing
        // alert. Reduced to a short alphanumeric slug here; the server clamps again.
        NSCharacterSet *disallowed = [[NSCharacterSet characterSetWithCharactersInString:
                                       @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"] invertedSet];
        NSString *slug = [[blockedBy componentsSeparatedByCharactersInSet:disallowed] componentsJoinedByString:@"-"];
        if (slug.length > 40) {
            slug = [slug substringToIndex:40];
        }
        reason = [NSString stringWithFormat:@"obscured-by-%@", slug];
    } else {
        reason = @"cover-not-on-screen";
    }
    return @{ @"ok": @NO, @"reason": reason };
}

// Recompute, self-heal, and publish to the locked page — but only when the answer CHANGED, so a
// steady state costs one CGWindowList call and no JS at all.
- (void)blinkeredEnforcementTick
{
    NSDictionary *verdict = [self blinkeredComputeEnforcementVerdict];
    if (!verdict) {
        _blinkeredLastEnforcementKey = nil;   // no verdict applies; re-publish when one next does
        return;
    }
    BOOL ok = [verdict[@"ok"] boolValue];
    NSString *reason = verdict[@"reason"] ?: @"";
    if (!ok) {
        // Self-healing: this is the path that recovers a lock the child re-broke by switching back
        // to the full-screen Space. Rate-limited inside.
        [self blinkeredEnsureOrdinarySpace:reason];
    }
    NSString *key = [NSString stringWithFormat:@"%d|%@", ok, reason];
    if ([key isEqualToString:_blinkeredLastEnforcementKey]) {
        return;
    }
    _blinkeredLastEnforcementKey = key;
    if (ok) {
        DDLogInfo(@"Blinkered: enforcement verified — the kiosk cover is on screen");
    } else {
        DDLogError(@"Blinkered: NOT ENFORCING (%@) — the kiosk is not covering the screen", reason);
    }
    [self blinkeredPublishEnforcement:ok reason:reason];
}

// Push the verdict into the locked page, which forwards it on its next heartbeat. A LIVE push,
// not a document-start constant like window.SafeExamBrowser.*: the verdict changes during a
// session, and a value baked in at page load would keep reporting a state that had already ended.
- (void)blinkeredPublishEnforcement:(BOOL)ok reason:(NSString *)reason
{
    NSWindow *mainWindow = self.browserController.mainBrowserWindow;
    if (!mainWindow) {
        return;
    }
    id abstractWebView = [mainWindow valueForKey:@"webView"];
    if (!abstractWebView || ![abstractWebView respondsToSelector:@selector(nativeWebView)]) {
        return;
    }
    id webView = [abstractWebView performSelector:@selector(nativeWebView)];
    if (![webView isKindOfClass:NSClassFromString(@"WKWebView")]) {
        return;
    }
    NSString *js = [NSString stringWithFormat:
                    @"window.__blinkeredEnforcement = { ok: %@, reason: %@, at: Date.now() }",
                    ok ? @"true" : @"false",
                    [SEBAbstractWebView blinkeredJSStringLiteral:reason]];
    @try {
        [webView performSelector:@selector(evaluateJavaScript:completionHandler:) withObject:js withObject:nil];
    } @catch (__unused NSException *exception) {}
}


- (void) coverScreens {
    DDLogDebug(@"%s Open background windows on all available screens", __FUNCTION__);
    // THE ORDERING FIX (#100). Covers created or re-framed while another app's full-screen Space is
    // current get associated with the OTHER Space and are never seen. Switch back first; everything
    // below then lands where the child is actually looking. No-op unless a full-screen Space is
    // current, rate-limited, and re-entrancy-guarded (this can call back into -coverScreens).
    [self blinkeredEnsureOrdinarySpace:@"cover-screens"];
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    BOOL allowSwitchToThirdPartyApps = ![preferences secureBoolForKey:@"org_safeexambrowser_elevateWindowLevels"];
    NSUInteger windowLevel;
    if (!allowSwitchToThirdPartyApps) {
        windowLevel = NSMainMenuWindowLevel+2;
    } else {
        windowLevel = NSNormalWindowLevel;
    }

    BOOL excludeMenuBar = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_showMenuBar"];

    // While the early session-launch covers are up, settings aren't applied yet
    // (elevateWindowLevels still reads NO) — keep the covers elevated and the
    // menu bar covered until startKioskMode levels everything per the config.
    if (_blinkeredEarlyCoversActive && _startingUp) {
        windowLevel = NSMainMenuWindowLevel+2;
        excludeMenuBar = NO;
    }

    // Adopt existing cap windows in place instead of closing + recreating them:
    // recreation is visible on macOS 26 (window open/close animates) and drops
    // the cover for a few frames. Only rebuild when the screen set changed.
    NSArray *screens = [NSScreen screens];
    if (self.capWindows.count > 0 && self.capWindows.count == screens.count) {
        NSMutableArray *unmatchedCapWindows = [self.capWindows mutableCopy];
        NSMutableArray *windowScreenPairs = [NSMutableArray new];
        BOOL allScreensMatched = YES;
        for (NSScreen *screen in screens) {
            // Match by frame overlap, not screen identity: macOS recreates the
            // NSScreen instances on every screen-parameters change (each
            // presentation-options switch during startup), and a window's .screen
            // can be transiently nil right after — geometry stays valid throughout.
            NSWindow *matchingWindow = nil;
            CGFloat bestOverlap = 0;
            for (NSWindow *capWindow in unmatchedCapWindows) {
                NSRect overlap = NSIntersectionRect(capWindow.frame, screen.frame);
                CGFloat overlapArea = overlap.size.width * overlap.size.height;
                if (overlapArea > bestOverlap) {
                    bestOverlap = overlapArea;
                    matchingWindow = capWindow;
                }
            }
            if (!matchingWindow) {
                allScreensMatched = NO;
                break;
            }
            [unmatchedCapWindows removeObject:matchingWindow];
            [windowScreenPairs addObject:@[matchingWindow, screen]];
        }
        if (allScreensMatched) {
            DDLogInfo(@"%s: adopting %lu existing cap window(s) in place (level %lu)", __FUNCTION__, (unsigned long)self.capWindows.count, (unsigned long)windowLevel);
            for (NSArray *pair in windowScreenPairs) {
                NSWindow *capWindow = pair[0];
                NSScreen *screen = pair[1];
                NSRect frame = screen.frame;
                if (excludeMenuBar && (floor(NSAppKitVersionNumber) >= NSAppKitVersionNumber10_10 || screen == screens[0])) {
                    frame.size.height -= screen.menuBarHeight;
                }
                [capWindow newSetLevel:windowLevel];
                [capWindow setFrame:frame display:YES];
            }
            return;
        }
    }
    // Screen set changed (or no covers yet): close any stale covers before
    // creating the new set, so no orphaned black window survives on a
    // disconnected/re-arranged screen.
    if (self.capWindows.count > 0) {
        [self closeCapWindows];
    }

    NSArray *backgroundCoveringWindows = [self fillScreensWithCoveringWindows:coveringWindowBackground windowLevel:windowLevel excludeMenuBar:excludeMenuBar];
    if (!self.capWindows) {
        self.capWindows = [NSMutableArray arrayWithArray:backgroundCoveringWindows];	// array for storing our cap (covering) background windows
    } else {
        [self.capWindows removeAllObjects];
        [self.capWindows addObjectsFromArray:backgroundCoveringWindows];
    }
}

                           
- (NSMutableArray *) fillScreensWithCoveringWindows:(coveringWindowKind)coveringWindowKind windowLevel:(NSUInteger)windowLevel excludeMenuBar:(BOOL)excludeMenuBar {
    NSMutableArray *coveringWindows = [NSMutableArray new];	// array for storing our cap (covering)  windows
    NSArray *screens = [NSScreen screens];	// get all available screens
    NSScreen *iterScreen;

    // Proposal B (MAC_WAKE_EDGE_RECOVERY_PLAN.md §2): HOME-lock background covers get the brand
    // backdrop instead of void black, so a paint/teardown failure never reads as a bricked Mac.
    // Living in the CREATION path is deliberate (review condition 3): covers are destroyed and
    // recreated on every screen-set change above, so a post-hoc paint of existing windows would
    // be lost on rebuild. Scope (review conditions 1+4): background kind ONLY — the lockdown
    // alert (red) and the coveringWindowModalAlert 0.4-alpha DIMMER stay untouched (branding the
    // dimmer would bleed a logo through every kiosk alert) — and only during a home lock;
    // exam/class covers stay pure black. Predicate = launch-time startURL check (covers are
    // created BEFORE the page loads, so the home_session.json predicate read "not home" on every
    // fresh lock and the covers stayed black — field-confirmed 4 Aug), OR'd with the session
    // file for mid-session robustness.
    BOOL blinkeredBrandCovers = coveringWindowKind == coveringWindowBackground
        && ([SEBBrowserWindow blinkeredIsHomeLockSession] || [self blinkeredHomeSessionInfo] != nil);

    for (iterScreen in screens)
    {
        NSDictionary *screenDeviceDescription = iterScreen.deviceDescription;
        BOOL inactive = iterScreen.inactive;
        DDLogDebug(@"Screen is %@active, device description: %@", inactive ? @"in" : @"", screenDeviceDescription);
        
        // NSRect frame = size of the current screen
        NSRect frame = [iterScreen frame];
        NSUInteger styleMask = NSWindowStyleMaskBorderless;
        NSRect rect = [NSWindow contentRectForFrameRect:frame styleMask:styleMask];
        
        // Set origin of the window rect to left bottom corner (important for non-main screens, since they have offsets)
        rect.origin.x = 0;
        rect.origin.y = 0;

        // If showing menu bar
        // On OS X >= 10.10 we exclude the menu bar on all screens from the covering windows
        // On OS X <= 10.9 we exclude the menu bar only on the screen which actually displays the menu bar
        if (excludeMenuBar && (floor(NSAppKitVersionNumber) >= NSAppKitVersionNumber10_10 || iterScreen == screens[0])) {
            // Reduce size of covering background windows to not cover the menu bar
            rect.size.height -= iterScreen.menuBarHeight;
        }
        DDLogDebug(@"Opening %@ covering window with frame %@ and window level %ld",
                   coveringWindowKind == coveringWindowBackground ? @"background" : @"lockdown alert",
                   (NSDictionary *)CFBridgingRelease(CGRectCreateDictionaryRepresentation(rect)), windowLevel);
        id window;
        id capview;
        NSColor *windowColor;
        switch (coveringWindowKind) {
            case coveringWindowBackground: {
                window = [[NSWindow alloc] initWithContentRect:rect styleMask:styleMask backing: NSBackingStoreBuffered defer:NO screen:iterScreen];
                capview = [[CapView alloc] initWithFrame:rect];
                if (blinkeredBrandCovers) {
                    windowColor = [SEBBrowserWindow blinkeredBrandBackdropColor];
                    [SEBBrowserWindow blinkeredAddBrandBackdropContentToView:capview];
                } else {
                    windowColor = [NSColor blackColor];
                }
                [window setAccessibilityElement:NO];
                break;
            }
                
            case coveringWindowLockdownAlert: {
                window = [[CapWindow alloc] initWithContentRect:rect styleMask:styleMask backing: NSBackingStoreBuffered defer:NO screen:iterScreen];
                capview = [[NSView alloc] initWithFrame:rect];
                windowColor = [NSColor redColor];
                break;
            }
                
            case coveringWindowModalAlert: {
                window = [[CapWindow alloc] initWithContentRect:rect styleMask:styleMask backing: NSBackingStoreBuffered defer:NO screen:iterScreen];
                capview = [[NSView alloc] initWithFrame:rect];
                windowColor = [NSColor blackColor];
                ((NSWindow *)window).alphaValue = 0.4;
                break;
            }
                
            default:
                return nil;
        }
        
        [window setReleasedWhenClosed:YES];
        [window setBackgroundColor:windowColor];
        // Covers appear/disappear in place — macOS 26 animates window open/close
        // (zoom + fade), which made every cover rebuild visible as a flicker.
        ((NSWindow *)window).animationBehavior = NSWindowAnimationBehaviorNone;
        if ([NSUserDefaults standardUserDefaults].allowWindowCapture == NO) {
            [window setSharingType: NSWindowSharingNone];  //don't allow other processes to read window contents
        }
        [window newSetLevel:windowLevel];
        //[window orderBack:self];
        [coveringWindows addObject: window];
        NSView *superview = [window contentView];
        [superview addSubview:capview];
        
        //[window orderBack:self];
        CapWindowController *capWindowController = [[CapWindowController alloc] initWithWindow:window];
        //CapWindow *loadedCapWindow = capWindowController.window;
        [capWindowController showWindow:self];
        [window makeKeyAndOrderFront:self];
        //[window orderBack:self];
        //BOOL isWindowLoaded = capWindowController.isWindowLoaded;
#ifdef DEBUG
        //DDLogDebug(@"Loaded capWindow %@, isWindowLoaded %@", loadedCapWindow, isWindowLoaded);
#endif
    }
    return coveringWindows;
}


// Cover currently intersected inactive screens and
// remove cover windows of no longer intersected screens
- (void) coverInactiveScreens:(NSArray *)inactiveScreens
{
    NSMutableArray *newCoverWindows = [NSMutableArray new];
    for (NSScreen *screen in inactiveScreens) {
        // Check if this screen is already covered
        BOOL isAlreadyCovered = false;
        NSUInteger i = 0;
        while (i < _inactiveScreenWindows.count) {
            CapWindow *coverWindow = _inactiveScreenWindows[i];
            if (coverWindow.screen == screen) {
                isAlreadyCovered = true;
                [newCoverWindows addObject:coverWindow];
                [_inactiveScreenWindows removeObject:coverWindow];
                break;
            } else {
                i++;
            }
        }
        if (!isAlreadyCovered) {
            CapWindow *newCoverWindow = [self coverInactiveScreen:screen];
            [newCoverWindows addObject:newCoverWindow];
        }
    }
    // Close covering windows if necessary
    for (CapWindow *coverWindowToClose in _inactiveScreenWindows) {
        [coverWindowToClose close];
    }
    _inactiveScreenWindows = newCoverWindows;
}


- (CapWindow *) coverInactiveScreen:(NSScreen *)screen
{
    NSRect frame = screen.frame;
    NSUInteger styleMask = NSWindowStyleMaskBorderless;
    NSRect rect = [NSWindow contentRectForFrameRect:frame styleMask:styleMask];
    
    // Set origin of the window rect to left bottom corner (important for non-main screens, since they have offsets)
    rect.origin.x = 0;
    rect.origin.y = 0;

    DDLogDebug(@"Opening inactive screen covering window with frame %@ ",
               (NSDictionary *)CFBridgingRelease(CGRectCreateDictionaryRepresentation(rect)));
    
    CapWindow *window = [[CapWindow alloc] initWithContentRect:rect styleMask:styleMask backing: NSBackingStoreBuffered defer:NO screen:screen];
    NSView *capview = [[NSView alloc] initWithFrame:rect];
    [window setReleasedWhenClosed:YES];
    [window setBackgroundColor:[NSColor orangeColor]];
    [window newSetLevel:NSScreenSaverWindowLevel];
    NSView *superview = [window contentView];
    [superview addSubview:capview];
    CapWindowController *capWindowController = [[CapWindowController alloc] initWithWindow:window];
    [capWindowController showWindow:self];
    [window makeKeyAndOrderFront:self];

    NSView *coveringView = window.contentView;
    [coveringView setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];
    [coveringView setTranslatesAutoresizingMaskIntoConstraints:YES];
    
    [coveringView addSubview:inactiveScreenCoverLabel];
    
    DDLogVerbose(@"Frame of superview: %f, %f", inactiveScreenCoverLabel.superview.frame.size.width, inactiveScreenCoverLabel.superview.frame.size.height);
    NSMutableArray *constraints = [NSMutableArray new];
    [constraints addObject:[NSLayoutConstraint constraintWithItem:inactiveScreenCoverLabel
                                                        attribute:NSLayoutAttributeCenterX
                                                        relatedBy:NSLayoutRelationEqual
                                                           toItem:inactiveScreenCoverLabel.superview
                                                        attribute:NSLayoutAttributeCenterX
                                                       multiplier:1.0
                                                         constant:0.0]];
    
    [constraints addObject:[NSLayoutConstraint constraintWithItem:inactiveScreenCoverLabel
                                                        attribute:NSLayoutAttributeCenterY
                                                        relatedBy:NSLayoutRelationEqual
                                                           toItem:inactiveScreenCoverLabel.superview
                                                        attribute:NSLayoutAttributeCenterY
                                                       multiplier:1.0
                                                         constant:0.0]];
    
    [inactiveScreenCoverLabel.superview addConstraints:constraints];

    return window;
}


// Called when changes of the screen configuration occur
// (new display is contected or removed or display mirroring activated)

- (void) adjustScreenLocking: (id _Nullable)sender
{
    // COALESCE, never skip. This handler re-frames the cap windows and re-lays the dock, and both
    // of those change the screen's visible frame — which re-fires
    // NSApplicationDidChangeScreenParametersNotification and calls this again. Normally it settles;
    // during the #100 incident it did not, and the log shows 226 passes at a 17 ms period, burning
    // CPU until the OS resource limit tripped.
    //
    // The floor below turns a storm into at most one pass per 200 ms, and the TRAILING pass is what
    // makes it safe: the last notification in a burst is still acted on, just once, so the final
    // screen state is always applied. A plain "drop if too soon" guard would lose it. A genuine
    // screen change (display connected) is unaffected — the first call always runs immediately.
    if (sender) {
        NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
        if (now - _blinkeredLastAdjustScreenLockingAt < 0.2) {
            if (!_blinkeredAdjustScreenLockingTrailingScheduled) {
                _blinkeredAdjustScreenLockingTrailingScheduled = YES;
                __weak typeof(self) weakSelf = self;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    typeof(self) strongSelf = weakSelf;
                    if (!strongSelf) { return; }
                    strongSelf.blinkeredAdjustScreenLockingTrailingScheduled = NO;
                    if (_blinkeredTeardownStarted) { return; }
                    [strongSelf adjustScreenLocking:nil];    // nil sender: runs the work, no re-coalescing
                });
            }
            return;
        }
        _blinkeredLastAdjustScreenLockingAt = now;
    }
    // This should only be done when the preferences window isn't open
    if (sender) {
        DDLogDebug(@"%s NSApplicationDidChangeScreenParametersNotification sender: %@", __FUNCTION__, sender);
    } else {
        DDLogDebug(@"%s", __FUNCTION__);
    }
    
    if (!_isTerminating && !self.settingsOpen) {
        
        // Close inactive screen covering windows if some are open
        for (CapWindow *coverWindowToClose in _inactiveScreenWindows) {
            [coverWindowToClose close];
        }
        
        // Switch off display mirroring if it isn't allowed
        [self conditionallyTerminateDisplayMirroring];
        DDLogDebug(@"Adjusting screen locking");
        
        // Check if lockdown windows are open and adjust those too
        if (self.lockdownWindows.count > 0) {
            DDLogDebug(@"Adjusting lockdown windows");
            NSDate *originalDidLockSEBTime = self.didLockSEBTime;
            [self closeCoveringWindows:self.lockdownWindows];
            [self openCoveringWindows];
            self.didLockSEBTime = originalDidLockSEBTime;
            DDLogDebug(@"Adjusting screen locking: didLockSEBTime %@, didBecomeActiveTime %@", self.didLockSEBTime, self.didBecomeActiveTime);
        }
        
        // Don't close + recreate the covering windows here: coverScreens adopts the
        // existing ones in place (re-level + re-frame) and only rebuilds when the
        // screen set actually changed. Recreating them on every screen-parameter
        // change is visible on macOS 26 (window open/close animates) — and this
        // fires on each presentation-options switch during startup, so it used to
        // churn through a fresh cover generation per kiosk-mode pass.
        // During startup we still re-cover whenever covers are already up (the early
        // session-launch ones, or the kiosk-start generation) — closing them here
        // mid-launch would expose the desktop.
        if (_isAACEnabled == NO && _wasAACEnabled == NO && (!_startingUp || self.capWindows.count > 0)) {
            [self coverScreens];
        } else {
            // AAC, or a startup path that never covers: just drop any stale covers.
            [self closeCapWindows];
        }
        
        // We adjust position and size of the SEB Dock
        [self.dockController adjustDock];
        
        // We adjust the size of the main browser window
        [self.browserController adjustMainBrowserWindow];
    }
}


// Called when main browser window changed screen
- (void) changeMainScreen: (id)sender
{
    [self.dockController moveDockToScreen:self.browserController.mainBrowserWindow.screen];
}


- (void) closeCapWindows
{
    [self closeCoveringWindows:self.capWindows];
}


#pragma mark - Managing Modal Alerts

- (NSAlert *) newAlert
{
    NSAlert *newAlert = [[NSAlert alloc] init];
    DDLogDebug(@"Adding modal alert window %@", newAlert.window);
    [_modalAlertWindows addObject:newAlert.window];
    if (self.aboutWindow.isVisible) {
        DDLogDebug(@"%s About SEB window is visible, attempting to close it.", __FUNCTION__);
        [self closeAboutWindow];
    }
    return newAlert;
}


- (void) removeAlertWindow:(NSWindow *)alertWindow
{
    if (alertWindow) {
        DDLogDebug(@"All modal alert windows %@", _modalAlertWindows);
        DDLogDebug(@"Removing modal alert window %@", alertWindow);
        [_modalAlertWindows removeObject:alertWindow];
        DDLogDebug(@"All modal alert windows after removing: %@", _modalAlertWindows);
    }
}


// ── E1 EXPERIMENT (3.6.200) — a sheet-preferring variant of the call below ─────────────────────
// Used by ONE caller: the offline panel. Everything else keeps -runModal unchanged.
//
// It routes through here rather than calling -beginSheetModalForWindow: directly so that the
// cover-window LEVELING still runs. run-empty-content-backdrop-test.sh C9 pins that for a reason it
// states plainly: "-runModal would put the only surface that names the way out BEHIND the covers."
// A sheet inherits its parent window's level, so the parent window is what must be raised — and a
// sheet nobody can see is worse than a modal one, because the parent loses the affordance entirely.
- (void) blinkeredRunSheetPreferringAlert:(NSAlert *)alert
                                forWindow:(NSWindow *)window
                        completionHandler:(void (^)(NSModalResponse returnCode))handler
{
    if (self.capWindows.count > 0) {
        [window newSetLevel:NSMainMenuWindowLevel+6];
    }
    [alert beginSheetModalForWindow:window completionHandler:handler];
}

- (void) runModalAlert:(NSAlert *)alert
conditionallyForWindow:(NSWindow *)window
     completionHandler:(void (^)(NSModalResponse returnCode))handler
{
    if (@available(macOS 12.0, *)) {
    } else {
        if (@available(macOS 11.0, *)) {
            if (_isAACEnabled || _wasAACEnabled) {
                [alert beginSheetModalForWindow:window completionHandler:(void (^)(NSModalResponse answer))handler];
                return;
            }
        }
    }
    // An alert must never end up behind the cover windows — especially the early
    // session-launch covers, which are up before the kiosk alert leveling applies.
    if (self.capWindows.count > 0) {
        [alert.window newSetLevel:NSMainMenuWindowLevel+6];
    }
    NSModalResponse answer = [alert runModal];
    if (handler) {
        handler(answer);
    }
}


#pragma mark - Displaying Specific Alerts

- (void)presentPreferencesCorruptedError
{
    DDLogError(@"Local SEB Settings Have Been Reset");
    
    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    NSAlert *modalAlert = [self newAlert];
    
    [modalAlert setMessageText:[NSString stringWithFormat:NSLocalizedString(@"Local %@ Settings Have Been Reset", @""), SEBShortAppName]];
    [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"Local preferences were created by an incompatible %@ version, damaged or manipulated. They have been reset to the default settings. Ask your exam supporter to re-configure %@ correctly.", @""), SEBShortAppName, SEBShortAppName]];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
    [modalAlert setAlertStyle:NSAlertStyleCritical];
    void (^preferencesCorruptedErrorOK)(NSModalResponse) = ^void (NSModalResponse answer) {
        [self removeAlertWindow:modalAlert.window];
        DDLogInfo(@"Dismissed alert for local SEB settings have been reset");
    };
    [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))preferencesCorruptedErrorOK];
}


#pragma mark - Lockdown Windows

// Handler called when SEB needs to be locked
- (void) lockSEB:(NSNotification*) notification
{
    self.didBecomeActiveTime = [NSDate date];
    DDLogDebug(@"lockSEB: %@", notification.name);
        
    dispatch_async(dispatch_get_main_queue(), ^{
        
        // Handler called when SEB resigns active state (by user switch / switch to login window)
        
        if ([[notification name] isEqualToString:
             NSWorkspaceSessionDidResignActiveNotification])
        {
            self.didResignActiveTime = [NSDate date];
            // Blinkered: a fast-user-switch or switch-to-login-window during a lock is NOT a tamper the
            // kid must clear with the quit/unlock password — that is upstream SEB's EXAM model, where an
            // invigilator is present to type it. Blinkered is a HOME browser: the kid doesn't know that
            // password, so the red "User Switch Locked" screen BRICKS them for a benign action (a parent
            // switching to the admin account, or sleep → login window → back — the exact false positive
            // reported on Maggie B's kids' Mac). The parent is still alerted reliably + independently by
            // the AGENT, which watches the console user during a lock and POSTs a `user_switch` security
            // event. So we do NOT show the lockdown screen here — we note it, and re-assert the kiosk
            // normally when the kid's session returns (below).
            DDLogInfo(@"SessionDidResignActive: user switch / switch to login window — will re-lock on return (no quit-password screen; agent alerts the parent)");
        }

        // Handler called when SEB becomes active again (after user switch / switch to login window)

        else if ([[notification name] isEqualToString:
                  NSWorkspaceSessionDidBecomeActiveNotification])
        {
            // Kid's locked session is frontmost again after the switch. Re-assert the lockdown NORMALLY
            // (re-cover the screens + kiosk, bring the locked page front) instead of the exam-style
            // quit-password screen — matching "it should have just locked down normally". Guard on
            // sessionRunning so a user switch while Blinkered is idle (no lock) never covers the screen.
            DDLogInfo(@"SessionDidBecomeActive: switched back after user switch / login window — reinforcing kiosk lockdown");
            if (self.sessionRunning) {
                [self reinforceKioskMode];
            }
        }
        
        // Handler called when attempting to re-open an exam which was interrupted before
        
        else if ([[notification name] isEqualToString:
                  @"detectedReOpeningExam"])
        {
            self.sessionState.reOpenedExamDetected = YES;
            
            [self.sebLockedViewController setLockdownAlertTitle: NSLocalizedString(@"Re-Opening Locked Exam!", @"Lockdown alert title text for re-opening a locked exam")
                                                        Message:[NSString stringWithFormat:@"%@\n\n%@",
                                                                 NSLocalizedString(@"This exam was interrupted before and not finished properly. Enter the quit/unlock password from the current session's settings, which usually exam supervision/support knows.", @""),
                                                                 [NSString stringWithFormat:NSLocalizedString(@"To avoid that %@ locks an exam, you have to always use a quit/unlock link after the exam was submitted or the quit button. Never restart your Mac while %@ is still running.", @""), SEBShortAppName, SEBShortAppName]
                                                                 ]];
            
            // Add log string for trying to re-open a locked exam
            [self appendErrorString:[NSString stringWithFormat:@"%@\n", NSLocalizedString(@"Re-opening an exam which was locked before", @"")] withTime:self.didBecomeActiveTime repeated:NO];
            
            [self openLockdownWindows];
        }
        
        // Handler called when screen sharing was detected
        
        else if ([[notification name] isEqualToString:
                  @"detectedScreenSharing"])
        {
            if (!self.sessionState.screenSharingDetected) {
                self.sessionState.screenSharingDetected = YES;
                self.sebLockedViewController.overrideCheckForScreenSharing.state = NO;
                self.sebLockedViewController.overrideCheckForScreenSharing.hidden = NO;
                
                // Set custom alert message string
                [self.sebLockedViewController setLockdownAlertTitle: [NSString stringWithFormat:NSLocalizedString(@"Screen Sharing Locked %@!", @"Lockdown alert title text for screen sharing"), SEBShortAppName]
                                                            Message:[NSString stringWithFormat:@"%@\n\n%@",
                                                                     NSLocalizedString(@"Screen sharing detected. Enter the quit/unlock password, which usually exam supervision/support knows.", @""),
                                                                     [NSString stringWithFormat:NSLocalizedString(@"To avoid that %@ locks itself during an exam when it detects that screen sharing started, it's best to switch off 'Screen Sharing' and 'Remote Management' in System Preferences/Sharing and 'Back to My Mac' in System Preferences/iCloud. You can also ask your network administrators to block ports used for the VNC protocol.", @""), SEBShortAppName]
                                                                     ]];
                
                // Report screen sharing is still active every 3rd second
                self->screenSharingLogCounter = logReportCounter;
                DDLogError(@"Screen sharing was activated!");
                
                if (self.sessionState.screenSharingCheckOverride == NO) {
                    [self openLockdownWindows];
                }
                
                // Add log string for screen sharing active
                [self appendErrorString:[NSString stringWithFormat:@"%@\n", NSLocalizedString(@"Screen sharing was activated", @"")] withTime:self.didBecomeActiveTime repeated:NO];
            } else {
                if (!self.lockdownWindows) {
                    self.sebLockedViewController.overrideCheckForScreenSharing.hidden = false;
                    [self openLockdownWindows];
                }
                // Add log string for screen sharing still active
                if (!self->screenSharingLogCounter--) {
                    [self appendErrorString:[NSString stringWithFormat:@"%@\n", NSLocalizedString(@"Screen sharing is still active", @"")] withTime:self.didBecomeActiveTime repeated:YES];
                    self->screenSharingLogCounter = logReportCounter;
                }
            }
        }
        
        // Handler called when Siri was detected
        
        else if ([[notification name] isEqualToString:
                  @"detectedSiri"])
        {
            if (!self.sessionState.siriDetected) {
                self.sessionState.siriDetected = YES;
                self.sebLockedViewController.overrideCheckForSiri.state = NO;
                self.sebLockedViewController.overrideCheckForSiri.hidden = NO;
                
                // Set custom alert message string
                [self.sebLockedViewController setLockdownAlertTitle:[NSString stringWithFormat:NSLocalizedString(@"Siri Locked %@!", @"Lockdown alert title text for Siri"), SEBShortAppName]
                                                            Message:NSLocalizedString(@"Siri activity detected. Enter the quit/unlock password, which usually exam supervision/support knows.", @"")];
                
                // Report Siri is still active every 3rd second
                self->siriLogCounter = logReportCounter;
                DDLogError(@"Siri activity detected!");
                
                if (self.sessionState.siriCheckOverride == NO) {
                    [self openLockdownWindows];
                }
                
                // Add log string for Siri active
                [self appendErrorString:[NSString stringWithFormat:@"%@\n", NSLocalizedString(@"Siri was activated", @"")] withTime:self.didBecomeActiveTime repeated:NO];
            } else {
                if (!self.lockdownWindows) {
                    self.sebLockedViewController.overrideCheckForSiri.hidden = false;
                    [self openLockdownWindows];
                }
                // Add log string for Siri still active
                if (!self->siriLogCounter--) {
                    [self appendErrorString:[NSString stringWithFormat:@"%@\n", NSLocalizedString(@"Siri is still active", @"")] withTime:self.didBecomeActiveTime repeated:YES];
                    self->siriLogCounter = logReportCounter;
                }
            }
        }
        
        // Handler called when dictation was detected
        
        else if ([[notification name] isEqualToString:
                  @"detectedDictation"])
        {
            if (!self.sessionState.dictationDetected) {
                self.sessionState.dictationDetected = YES;
                self.sebLockedViewController.overrideCheckForDictation.state = NO;
                self.sebLockedViewController.overrideCheckForDictation.hidden = NO;
                
                // Set custom alert message string
                [self.sebLockedViewController setLockdownAlertTitle:[NSString stringWithFormat:NSLocalizedString(@"Dictation Locked %@!", @"Lockdown alert title text for Siri"), SEBShortAppName]
                                                            Message:NSLocalizedString(@"Dictation activity detected. Enter the quit/unlock password, which usually exam supervision/support knows.", @"")];
                
                // Report dictation is still active every 3rd second
                self->dictationLogCounter = logReportCounter;
                DDLogError(@"Dictation was activated!");
                
                if (self.sessionState.dictationCheckOverride == NO) {
                    [self openLockdownWindows];
                }
                
                // Add log string for dictation active
                [self appendErrorString:[NSString stringWithFormat:@"%@\n", NSLocalizedString(@"Dictation was activated", @"")] withTime:self.didBecomeActiveTime repeated:NO];
            } else {
                if (!self.lockdownWindows) {
                    self.sebLockedViewController.overrideCheckForDictation.hidden = false;
                    [self openLockdownWindows];
                }
                // Add log string for dictation still active
                if (!self->dictationLogCounter--) {
                    [self appendErrorString:[NSString stringWithFormat:@"%@\n", NSLocalizedString(@"Dictation is still active", @"")] withTime:self.didBecomeActiveTime repeated:YES];
                    self->dictationLogCounter = logReportCounter;
                }
            }
        }
        
        // Handler called when a prohibited process was detected
        
        else if ([[notification name] isEqualToString:
                  @"detectedProhibitedProcess"])
        {
            
            // Add log string for detected prohibited processes
            NSArray *allRunningProhibitedProcesses = self.runningProhibitedProcesses.copy;
            NSMutableSet *runningProhibitedProcesses = NSMutableSet.new;
            NSMutableSet *runningOverriddenProhibitedProcesses = NSMutableSet.new;
            for (NSDictionary* runningProhibitedProcess in allRunningProhibitedProcesses) {
                if ([self isOverriddenProhibitedProcess:runningProhibitedProcess]) {
                    [runningOverriddenProhibitedProcesses addObject:runningProhibitedProcess[@"name"]];
                } else {
                    [runningProhibitedProcesses addObject:runningProhibitedProcess];
                }
            }
                        
            if (!self.sessionState.processesDetected) {
                self.sessionState.processesDetected = YES;
                self.sebLockedViewController.overrideCheckForSpecifcProcesses.state = NO;
                self.sebLockedViewController.overrideCheckForSpecifcProcesses.hidden = NO;
                self.sebLockedViewController.overrideCheckForAllProcesses.state = NO;
                self.sebLockedViewController.overrideCheckForAllProcesses.hidden = NO;
                
                // Set custom alert message string
                [self.sebLockedViewController setLockdownAlertTitle:[NSString stringWithFormat:NSLocalizedString(@"Prohibited Process Locked %@!", @"Lockdown alert title text for prohibited process"), SEBShortAppName]
                                                            Message:[NSString stringWithFormat:NSLocalizedString(@"%@ is locked because a process, which isn't allowed to run cannot be terminated. Enter the quit/unlock password, which usually exam supervision/support knows.", @""), SEBShortAppName]];
                
                // Report processes are still active every 3rd second
                self->prohibitedProcessesLogCounter = logReportCounter;
                DDLogError(@"Prohibited processes detected: %@", allRunningProhibitedProcesses);
                
                if (self.sessionState.processCheckAllOverride == NO) {
                    if (self.sessionState.overriddenProhibitedProcesses.count > 0) {
                        // If checking of some processes was overriden, check if newly reported processes are overridden
                        for (NSDictionary* runningProhibitedProcess in allRunningProhibitedProcesses) {
                            if (![self isOverriddenProhibitedProcess:runningProhibitedProcess]) {
                                // Check for newly reported prohibited process was not overridden before: Open lock screen
                                DDLogDebug(@"Check for running prohibited process %@ was not overridden before", runningProhibitedProcess);
                                [self openLockdownWindows];
                                break;
                            } else {
                                DDLogDebug(@"Check for running prohibited process %@ was overridden before", runningProhibitedProcess);
                            }
                        }
                    } else {
                        // No previously overridden processes: Open lock screen
                        [self openLockdownWindows];
                    }
                }
                // Add log string for prohibited process detected
                [self appendErrorStringsFor:runningOverriddenProhibitedProcesses runningProhibitedProcesses:runningProhibitedProcesses repeated:NO];
                
            } else {
                if (!self.lockdownWindows) {
                    self.sebLockedViewController.overrideCheckForSpecifcProcesses.hidden = NO;
                    self.sebLockedViewController.overrideCheckForAllProcesses.hidden = NO;
                    [self openLockdownWindows];
                }
                
                if (!self->prohibitedProcessesLogCounter--) {
                    [self appendErrorStringsFor:runningOverriddenProhibitedProcesses runningProhibitedProcesses:runningProhibitedProcesses repeated:YES];
                    self->prohibitedProcessesLogCounter = logReportCounter;
                }
            }
        }
        
        // Handler called when a SIGSTOP was detected
        
        else if ([[notification name] isEqualToString:
                  @"detectedSIGSTOP"])
        {
#ifndef DEBUG
            
            [self.sebLockedViewController setLockdownAlertTitle: [NSString stringWithFormat:NSLocalizedString(@"%@ Process Was Stopped!", @"Lockdown alert title text for SEB process was stopped"), SEBShortAppName]
                                                        Message:[NSString stringWithFormat:NSLocalizedString(@"The %@ process was interrupted, which can indicate manipulation. Enter the quit/unlock password, which usually exam supervision/support knows.", @""), SEBShortAppName]];
            // Add log string for trying to re-open a locked exam
            // Calculate time difference between session resigning active and becoming active again
            NSCalendar *calendar = [[NSCalendar alloc] initWithCalendarIdentifier:NSCalendarIdentifierGregorian];
            NSDateComponents *components = [calendar components:NSCalendarUnitMinute | NSCalendarUnitSecond
                                                       fromDate:self->timeProcessCheckBeforeSIGSTOP
                                                         toDate:self.didBecomeActiveTime
                                                        options:NSCalendarWrapComponents];
            [self appendErrorString:[NSString stringWithFormat:@"%@\n", [NSString stringWithFormat:NSLocalizedString(@"%@ process was stopped for %ld:%.2ld (minutes:seconds)", @""), SEBShortAppName, components.minute, components.second]] withTime:self.didBecomeActiveTime repeated:NO];
            
            if (!self.lockdownWindows) {
                [self openLockdownWindows];
                self.didLockSEBTime = self->timeProcessCheckBeforeSIGSTOP;
            }
#endif
        }
        
        // Handler called when there is no required built-in display available
        
        else if ([[notification name] isEqualToString:
                  @"detectedRequiredBuiltinDisplayMissing"])
        {
            if (self.sessionState.builtinDisplayNotAvailableDetected == NO) {
                if (!self.settingsOpen && !self.openingSettings) {
                    // Don't display the alert or lock screen while opening new settings
                    if ((self.startingUp || self.restarting)) {
                        // SEB is starting, we give the option to quit
                        NSAlert *modalAlert = [self newAlert];
                        [modalAlert setMessageText:NSLocalizedString(@"No Built-In Display Available!", @"")];
                        [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"A built-in display is required, but not available. If you're using a MacBook, use its internal display and start %@ again.", @""), SEBShortAppName]];
                        [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
                        [modalAlert setAlertStyle:NSAlertStyleCritical];
                        void (^vmDetectedHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                            [self removeAlertWindow:modalAlert.window];
                            [self quitSEBOrSession];
                        };
                        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))vmDetectedHandler];
                        return;
                    }
                    self.sessionState.builtinDisplayNotAvailableDetected = YES;
                    if (self.sessionState.builtinDisplayEnforceOverride == NO && !self.settingsOpen) {
                        self.sebLockedViewController.overrideEnforcingBuiltinScreen.state = false;
                        self.sebLockedViewController.overrideEnforcingBuiltinScreen.hidden = false;
                        [self.sebLockedViewController setLockdownAlertTitle: NSLocalizedString(@"No Built-In Display Available!", @"Lockdown alert title text for no required built-in display available")
                                                                    Message:NSLocalizedString(@"A built-in display is required, but not available. If you're using a MacBook, use its internal display. To override this requirement, select the option below and enter the quit/unlock password, which usually exam supervision/support knows.", @"")];
                    }
                    [self appendErrorString:[NSString stringWithFormat:@"%@\n", NSLocalizedString(@"No built-in display available, although required in settings!", @"")] withTime:self.didBecomeActiveTime repeated:NO];
                    
                    if (self.sessionState.builtinDisplayEnforceOverride == NO) {
                        [self openLockdownWindows];
                    }
                }
            } else {
                DDLogDebug(@"%s: self.sessionState.builtinDisplayNotAvailableDetected == YES", __FUNCTION__);
                if (self.sessionState.noRequiredBuiltInScreenAvailable == NO) {
                    DDLogDebug(@"%s: self.sessionState.noRequiredBuiltInScreenAvailable == NO", __FUNCTION__);
                    // Previously there was no built-in display detected and SEB locked, now there is one available
                    // this can happen on a MacBook when the display lid was closed and now opened again
                    // if there was no previous lock message, we can close the lockdown screen
                    self.sessionState.builtinDisplayNotAvailableDetected = NO;
                    self.sebLockedViewController.overrideEnforcingBuiltinScreen.hidden = YES;
                    DDLogDebug(@"%s: _sebLockedViewController %@, quitInsteadUnlockingButton.state: %ld", __FUNCTION__, self.sebLockedViewController, (long)self.sebLockedViewController.quitInsteadUnlockingButton.state);
                    self.sebLockedViewController.quitInsteadUnlockingButton.state = NO;
                    DDLogDebug(@"%s: _sebLockedViewController.quitInsteadUnlockingButton.state: %ld", __FUNCTION__, (long)self.sebLockedViewController.quitInsteadUnlockingButton.state);
                    [self conditionallyCloseLockdownWindows];
                }
            }
        }
        
        // Handler called when dictation was detected
        
        else if ([[notification name] isEqualToString:
                  @"proctoringFailed"])
        {
            self.sessionState.proctoringFailedDetected = YES;
            // Set custom alert message string
            NSString *proctoringFailedErrorString = [notification.userInfo objectForKey:NSLocalizedFailureReasonErrorKey];
            [self.sebLockedViewController setLockdownAlertTitle:[NSString stringWithFormat:NSLocalizedString(@"Proctoring Error Locked %@!", @"Lockdown alert title text for proctoring failure"), SEBShortAppName]
                                                        Message:[NSString stringWithFormat:NSLocalizedString(@"Proctoring failed with error '%@'. Enter the quit/unlock password, which usually exam supervision/support knows.", @""), proctoringFailedErrorString]];
            self.sebLockedViewController.retryButton.hidden = NO;
            
            // Add log string for proctoring failed
            [self appendErrorString:[NSString stringWithFormat:@"%@%@\n", NSLocalizedString(@"Proctoring failed: ", @""), proctoringFailedErrorString] withTime:self.didBecomeActiveTime repeated:self.zoomUserRetryWasUsed];
            
            [self openLockdownWindows];
        } else {
            NSString *lockReason;
            BOOL isDisabled = NO;
            NSDictionary *userInfo = notification.userInfo;
            if (userInfo) {
                lockReason = [userInfo valueForKey:@"lockReason"];
                isDisabled = [[userInfo valueForKey:@"isDisabled"] boolValue];
            }
            NSString *message;
            NSString *logMessage;
            if (isDisabled) {
                message = [NSString stringWithFormat:NSLocalizedString(@"%@ is disabled. Enable %@ and restart %@.", @""), lockReason, lockReason, SEBShortAppName];
                logMessage = [NSString stringWithFormat:NSLocalizedString(@"%@ is disabled!", @""), lockReason];
            } else {
                message = [NSString stringWithFormat:@"%@", lockReason ? lockReason : NSLocalizedString(@"Please contact your exam support.", @"")];
                logMessage = lockReason;
            }
            DDLogError(@"Lock Reason: %@", lockReason);
            [self.sebLockedViewController setLockdownAlertTitle: [NSString stringWithFormat:NSLocalizedString(@"%@ is Locked!", @""), SEBShortAppName]
                                                        Message:message];
            [self appendErrorString:[NSString stringWithFormat:@"%@\n", logMessage] withTime:self.didBecomeActiveTime repeated:NO];
            [self openLockdownWindowsQuitOnly:isDisabled];
        }

    });
}


- (void) appendErrorString:(NSString *)errorString withTime:(NSDate *)errorTime repeated:(BOOL)repeated
{
    if (!repeated &&
        (_establishingSEBServerConnection || _sebServerConnectionEstablished)) {
        NSInteger notificationID = [self.serverController sendLockscreenWithMessage:[NSString stringWithFormat:@"%@", errorString]];
        NSNumber *notificationIDNumber = [NSNumber numberWithInteger:notificationID];
        [self.sebServerPendingLockscreenEvents addObject:notificationIDNumber];
    }
    [self.sebLockedViewController appendErrorString:errorString withTime:errorTime];
}


- (void)appendErrorStringsFor:(NSMutableSet *)runningOverriddenProhibitedProcesses
   runningProhibitedProcesses:(NSMutableSet *)runningProhibitedProcesses
                     repeated:(BOOL)repeated {
    if (runningProhibitedProcesses.count > 0) {
        NSArray *runningProhibitedProcessesArray = repeated ? [runningProhibitedProcesses valueForKey:@"name"] : [runningProhibitedProcesses allObjects];
        [self appendErrorString:[NSString stringWithFormat:@"%@: %@\n", NSLocalizedString(@"Prohibited processes detected", @""), runningProhibitedProcessesArray] withTime:self.didBecomeActiveTime repeated:repeated];
    }
    if (runningOverriddenProhibitedProcesses.count > 0) {
        [self appendErrorString:[NSString stringWithFormat:@"%@: %@\n", NSLocalizedString(@"Prohibited processes (check overridden) still running", @""), runningOverriddenProhibitedProcesses] withTime:self.didBecomeActiveTime repeated:repeated];
    }
}


- (NSMutableArray *) sebServerPendingLockscreenEvents
{
    if (!_sebServerPendingLockscreenEvents) {
        _sebServerPendingLockscreenEvents = [NSMutableArray new];
    }
    return _sebServerPendingLockscreenEvents;
}


- (BOOL) conditionallyLockExam:(NSString *)examURLString configKey:(NSData *)configKey
{
    if ([self.sebLockedViewController isStartingLockedExam:examURLString configKey:configKey]) {
        // Blinkered: a previous session of this exam wasn't ended via a quit-link — almost
        // always because the parent/teacher unlocked remotely and the agent force-quit
        // Blinkered (a hard kill). That's normal operation for Blinkered, not manipulation,
        // so clear the stale locked-exam record and start the session fresh instead of
        // showing the "Re-Opening Locked Exam" recovery screen, which demands the random
        // per-session quit password that nobody knows.
        DDLogInfo(@"Blinkered: clearing stale locked-exam record (previous session force-quit on unlock) and starting fresh");
        [self.sebLockedViewController removeLockedExam:examURLString configKey:configKey];
    }
    return NO;
}


- (void) openLockdownWindows
{
    [self openLockdownWindowsQuitOnly:NO];
}

- (void) openLockdownWindowsQuitOnly:(BOOL)quitOnly
{
    if (!self.lockdownWindows) {
        self.didLockSEBTime = [NSDate date];
        DDLogDebug(@"openLockdownWindows: didLockSEBTime %@, didBecomeActiveTime %@", self.didLockSEBTime, self.didBecomeActiveTime);

        DDLogError(@"Locking SEB with red frontmost covering windows");
        [self openCoveringWindows];
        NSAccessibilityPostNotification(_sebLockedViewController.view.window, NSAccessibilityFocusedWindowChangedNotification);
        if (quitOnly) {
            _sebLockedViewController.quitUnlockPasswordUI.hidden = YES;
            _sebLockedViewController.quitOnlyButton.hidden = NO;
        } else {
            _sebLockedViewController.quitUnlockPasswordUI.hidden = NO;
            _sebLockedViewController.quitOnlyButton.hidden = YES;
        }
        lockdownModalSession = [NSApp beginModalSessionForWindow:self.lockdownWindows[0]];
        [NSApp runModalSession:lockdownModalSession];
    }
}


- (NSData *)configKey {
    return self.browserController.configKey;
}


- (void) retryButtonPressed
{
    DDLogDebug(@"%s", __FUNCTION__);
}

- (void) successfullyRetriedToConnect
{
    self.sessionState.proctoringFailedDetected = NO;
    [self conditionallyCloseLockdownWindows];
}


- (void) correctPasswordEntered
{
#ifdef DEBUG
    DDLogInfo(@"%s, _sebLockedViewController %@", __FUNCTION__, _sebLockedViewController);
#endif
    [_sebLockedViewController shouldCloseLockdownWindows];
}


- (NSURL *) startURL
{
    return self.sessionState.startURL;
}


- (void) conditionallyCloseLockdownWindows
{
    if (_sebLockedViewController.overrideCheckForScreenSharing.hidden &&
        _sebLockedViewController.overrideEnforcingBuiltinScreen.hidden &&
        _sebLockedViewController.overrideCheckForSiri.hidden &&
        _sebLockedViewController.overrideCheckForDictation.hidden &&
        _sebLockedViewController.overrideCheckForSpecifcProcesses.hidden &&
        _sebLockedViewController.overrideCheckForAllProcesses.hidden &&
        !self.sessionState.proctoringFailedDetected &&
        !self.sessionState.userSwitchDetected) {
        DDLogDebug(@"%s: close lockdown windows", __FUNCTION__);
        [self closeLockdownWindowsAllowOverride:YES];
    }
}

- (void) closeLockdownWindowsAllowOverride:(BOOL)allowOverride
{
    if (self.lockdownWindows) {
        DDLogError(@"Unlocking SEB, removing red frontmost covering windows");

        [NSApp endModalSession:lockdownModalSession];

        if (_sebLockedViewController.overrideCheckForScreenSharing.state == YES) {
            DDLogInfo(@"%s: overrideCheckForScreenSharing selected", __FUNCTION__);
            self.sessionState.screenSharingCheckOverride = allowOverride;
            _sebLockedViewController.overrideCheckForScreenSharing.state = NO;
            _sebLockedViewController.overrideCheckForScreenSharing.hidden = YES;
        }

        if (_sebLockedViewController.overrideEnforcingBuiltinScreen.state == YES) {
            DDLogInfo(@"%s: overrideEnforcingBuiltinScreen selected", __FUNCTION__);
            if (allowOverride) {
                self.sessionState.builtinDisplayEnforceOverride = YES;
                self.sessionState.builtinDisplayNotAvailableDetected = NO;
            }
            _sebLockedViewController.overrideEnforcingBuiltinScreen.state = NO;
            _sebLockedViewController.overrideEnforcingBuiltinScreen.hidden = YES;
        }

        if (_sebLockedViewController.overrideCheckForSiri.state == YES) {
            DDLogInfo(@"%s: overrideCheckForSiri selected", __FUNCTION__);
            self.sessionState.siriCheckOverride = allowOverride;
            _sebLockedViewController.overrideCheckForSiri.state = NO;
            _sebLockedViewController.overrideCheckForSiri.hidden = YES;
        }
        
        if (_sebLockedViewController.overrideCheckForDictation.state == YES) {
            DDLogInfo(@"%s: overrideCheckForDictation selected", __FUNCTION__);
            self.sessionState.dictationCheckOverride = allowOverride;
            _sebLockedViewController.overrideCheckForDictation.state = NO;
            _sebLockedViewController.overrideCheckForDictation.hidden = YES;
        }
        
        if (_sebLockedViewController.overrideCheckForSpecifcProcesses.state == YES) {
            DDLogInfo(@"%s: overrideCheckForSpecifcProcesses selected", __FUNCTION__);
            if (allowOverride) {
                self.sessionState.processCheckSpecificOverride = YES;
                if (_runningProhibitedProcesses.count > 0) {
                    if (!self.sessionState.overriddenProhibitedProcesses) {
                        self.sessionState.overriddenProhibitedProcesses = _runningProhibitedProcesses.copy;
                    } else {
                        self.sessionState.overriddenProhibitedProcesses = [self.sessionState.overriddenProhibitedProcesses arrayByAddingObjectsFromArray:_runningProhibitedProcesses];
                    }
                    // Check if overridden processes are prohibited BSD processes from settings
                    // and remove them from the list of the periodically called process watcher checks
                    [[ProcessManager sharedProcessManager] removeOverriddenProhibitedBSDProcesses:self.sessionState.overriddenProhibitedProcesses];
                    DDLogInfo(@"%s: overrideCheckForSpecifcProcesses: %@", __FUNCTION__, self.sessionState.overriddenProhibitedProcesses);
                }
            }
            _sebLockedViewController.overrideCheckForSpecifcProcesses.state = NO;
            _sebLockedViewController.overrideCheckForSpecifcProcesses.hidden = YES;
            self.sessionState.processesDetected = NO;
        }
        
        if (_sebLockedViewController.overrideCheckForAllProcesses.state == YES) {
            DDLogInfo(@"%s: overrideCheckForAllProcesses selected", __FUNCTION__);
            self.sessionState.processCheckAllOverride = allowOverride;
            _sebLockedViewController.overrideCheckForAllProcesses.state = NO;
            _sebLockedViewController.overrideCheckForAllProcesses.hidden = YES;
        }
        
        if (self.sessionState.screenSharingCheckOverride == NO) {
            self.sessionState.screenSharingDetected = NO;
        }
        lastTimeProcessCheck = [NSDate date];
        _SIGSTOPDetected = NO;
        
        self.sessionState.proctoringFailedDetected = NO;
        _zoomUserRetryWasUsed = NO;
        self.sessionState.userSwitchDetected = NO;
        _sebLockedViewController.retryButton.hidden = YES;
        if (self.sebServerPendingLockscreenEvents.count > 0) {
            [self.serverController confirmLockscreensWithUIDs:self.sebServerPendingLockscreenEvents.copy];
            [self.sebServerPendingLockscreenEvents removeAllObjects];
        }
        
        if (allowOverride) {
            DDLogDebug(@"%s: _sebLockedViewController %@, quitInsteadUnlockingButton.state: %ld", __FUNCTION__, _sebLockedViewController, (long)_sebLockedViewController.quitInsteadUnlockingButton.state);
            if (_sebLockedViewController.quitInsteadUnlockingButton.state == YES) {
                DDLogInfo(@"%s: overrideCheckForDictation selected", __FUNCTION__);
                _sebLockedViewController.quitInsteadUnlockingButton.state = NO;
                [self quitSEBOrSession];
            }
        } else {
            _sebLockedViewController.quitInsteadUnlockingButton.state = NO;
        }

        [_sebLockedViewController.view removeFromSuperview];
        [self closeCoveringWindows:self.lockdownWindows];
        self.lockdownWindows = nil;
    } else {
        DDLogDebug(@"%s but there are no open lockdown windows anymore, returning.", __FUNCTION__);
    }
}


- (void) openCoveringWindows
{
    DDLogDebug(@"%s", __FUNCTION__);

    self.lockdownWindows = [self fillScreensWithCoveringWindows:coveringWindowLockdownAlert
                                                    windowLevel:NSScreenSaverWindowLevel
                                                 excludeMenuBar:false];
    NSWindow *coveringWindow = self.lockdownWindows[0];
    NSView *coveringView = coveringWindow.contentView;
    [coveringView setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];
    [coveringView setTranslatesAutoresizingMaskIntoConstraints:true];
    
    _sebLockedViewController.sebController = self;
    
    [coveringView addSubview:_sebLockedViewController.view];
    
    DDLogVerbose(@"Frame of superview: %f, %f", _sebLockedViewController.view.superview.frame.size.width, _sebLockedViewController.view.superview.frame.size.height);
    NSMutableArray *constraints = [NSMutableArray new];
    [constraints addObject:[NSLayoutConstraint constraintWithItem:_sebLockedViewController.view
                                                        attribute:NSLayoutAttributeCenterX
                                                        relatedBy:NSLayoutRelationEqual
                                                           toItem:_sebLockedViewController.view.superview
                                                        attribute:NSLayoutAttributeCenterX
                                                       multiplier:1.0
                                                         constant:0.0]];
    
    [constraints addObject:[NSLayoutConstraint constraintWithItem:_sebLockedViewController.view
                                                        attribute:NSLayoutAttributeCenterY
                                                        relatedBy:NSLayoutRelationEqual
                                                           toItem:_sebLockedViewController.view.superview
                                                        attribute:NSLayoutAttributeCenterY
                                                       multiplier:1.0
                                                         constant:0.0]];

    [_sebLockedViewController.view.superview addConstraints:constraints];
}


- (void) closeCoveringWindows:(NSMutableArray *)windows
{
    DDLogDebug(@"%s: %@", __FUNCTION__, windows);

    // Close the covering windows
	NSUInteger windowIndex;
	NSUInteger windowCount = [windows count];
    for (windowIndex = 0; windowIndex < windowCount; windowIndex++ )
    {
		[(NSWindow *)[windows objectAtIndex:windowIndex] close];
	}
    [windows removeAllObjects];
}


- (void) openInfoHUD:(NSString *)lockedTimeInfo
{
    informationHUDLabel.font = [NSFont boldSystemFontOfSize:[NSFont systemFontSize]];   
    informationHUDLabel.textColor = [NSColor whiteColor];
    NSMutableString *informationText = [NSMutableString stringWithString:(lockedTimeInfo)];
    
    if (self.sessionState.reOpenedExamDetected) {
        informationHUDLabel.textColor = [NSColor redColor];
        [informationText appendString:[NSString stringWithFormat:@"\n\n%@",
                                       NSLocalizedString(@"Previously interrupted exam was re-opened!", @"")]];
        self.sessionState.reOpenedExamDetected = NO;
    }
    
    if (self.sessionState.screenSharingCheckOverride) {
        informationHUDLabel.textColor = [NSColor redColor];
        [informationText appendString:[NSString stringWithFormat:@"\n\n%@",
                                       NSLocalizedString(@"Detecting screen sharing was disabled!", @"")]];
    }
    
    if (self.sessionState.siriCheckOverride) {
        informationHUDLabel.textColor = [NSColor redColor];
        [informationText appendString:[NSString stringWithFormat:@"\n\n%@",
                                       NSLocalizedString(@"Detecting Siri was disabled!", @"")]];
    }
    
    if (self.sessionState.dictationCheckOverride) {
        informationHUDLabel.textColor = [NSColor redColor];
        [informationText appendString:[NSString stringWithFormat:@"\n\n%@",
                                       NSLocalizedString(@"Detecting dictation was disabled!", @"")]];
    }
    
    if (self.sessionState.processCheckAllOverride) {
        informationHUDLabel.textColor = [NSColor redColor];
        [informationText appendString:[NSString stringWithFormat:@"\n\n%@",
                                       NSLocalizedString(@"Detecting processes was completely disabled!", @"")]];
    } else if (self.sessionState.processCheckSpecificOverride) {
        informationHUDLabel.textColor = [NSColor redColor];
        [informationText appendString:[NSString stringWithFormat:@"\n\n%@",
                                       NSLocalizedString(@"Detecting specific processes was disabled!", @"")]];
    }
    
    NSString *informationTextFinal = [informationText copy];
    [informationHUDLabel setStringValue:informationTextFinal];
    NSArray *screens = [NSScreen screens];    // get all available screens
    NSScreen *mainScreen = screens[0];
    
    NSPoint topLeftPoint;
    topLeftPoint.x = mainScreen.frame.origin.x + mainScreen.frame.size.width - informationHUD.frame.size.width - mainScreen.menuBarHeight;
    topLeftPoint.y = mainScreen.frame.origin.y + mainScreen.frame.size.height - 44;
    [informationHUD setFrameTopLeftPoint:topLeftPoint];
    
    informationHUD.becomesKeyOnlyIfNeeded = YES;
    [informationHUD setLevel:NSModalPanelWindowLevel];
    DDLogDebug(@"Opening info HUD: %@", informationTextFinal);
    [informationHUD makeKeyAndOrderFront:nil];
}


- (void) openLockModalWindows
{
    self.lockModalWindows = [self fillScreensWithCoveringWindows:coveringWindowModalAlert
                                                    windowLevel:NSScreenSaverWindowLevel
                                                 excludeMenuBar:false];
}

- (void) closeLockModalWindows
{
    [self closeCoveringWindows:self.lockModalWindows];
}


#pragma mark - Managing Other Running Applications

- (void) startTask {
	// Start third party application from within SEB
	
	// Path to Excel
	NSString *pathToTask=@"/Applications/Preview.app/Contents/MacOS/Preview";
	
	// Parameter and path to XUL-SEB Application
	NSArray *taskArguments=[NSArray arrayWithObjects:@"", nil];
	
	// Allocate and initialize a new NSTask
    NSTask *task=[[NSTask alloc] init];
	
	// Tell the NSTask what the path is to the binary it should launch
    [task setLaunchPath:pathToTask];
    
    // The argument that we pass to XULRunner (in the form of an array) is the path to the SEB-XUL-App
    [task setArguments:taskArguments];
    	
	// Launch the process asynchronously
	@try {
		[task launch];
	}
	@catch (NSException * e) {
		DDLogError(@"Error.  Make sure you have a valid path and arguments.");
		
	}
}


// hide all other applications if not in debug build setting
// Check if the app is listed in prohibited processes
- (void) regainActiveStatus: (id _Nullable)sender
{
    // Atomic teardown (M0): once exitSEB has begun, SEB must never re-assert itself. Hiding our
    // windows activates the next app and restoring the presentation options changes them — both of
    // which land here, and re-activating, re-raising the main browser window and re-hiding the kid's
    // apps would fight the revealed desktop until the process dies. The observers feeding this are
    // removed at the same moment; this gate catches anything already in flight.
    if (_blinkeredTeardownStarted) {
        DDLogDebug(@"%s: teardown started, not regaining active status", __FUNCTION__);
        return;
    }

#ifdef DEBUG
    DDLogInfo(@"%s: Notification:  %@", __FUNCTION__, [sender name]);
#endif

    NSDictionary *userInfo = [sender userInfo];
    if (userInfo) {
        NSRunningApplication *launchedApp = [userInfo objectForKey:NSWorkspaceApplicationKey];
#ifdef DEBUG
        DDLogInfo(@"Activated app localizedName: %@, bundle ID: %@, executableURL: %@", launchedApp.localizedName, launchedApp.bundleIdentifier, launchedApp.executableURL);
#endif
        if (systemPreferencesOpenedForScreenRecordingPermissions && [launchedApp.bundleIdentifier isEqualToString:systemPreferencesBundleID]) {
            systemPreferencesOpenedForScreenRecordingPermissions = NO;
            [NSApp abortModal];
        }
    }
    
    // Load preferences from the system's user defaults database
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    BOOL allowSwitchToThirdPartyApps = ![preferences secureBoolForKey:@"org_safeexambrowser_elevateWindowLevels"];
    if (!allowSwitchToThirdPartyApps && !self.settingsOpen && !fontRegistryUIAgentRunning) {
        // if switching to ThirdPartyApps not allowed
        DDLogDebug(@"Regain active status after %@", [sender name]);
#ifndef DEBUG
        [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
        if (_isAACEnabled == NO && _wasAACEnabled == NO) {
            [[NSWorkspace sharedWorkspace] performSelectorOnMainThread:@selector(hideOtherApplications) withObject:NULL waitUntilDone:NO];
        }
#endif
        [self.browserController.mainBrowserWindow makeKeyAndOrderFront:self];
//        [self.browserController.mainBrowserWindow makeMainWindow];
//        [self.browserController.mainBrowserWindow makeActiveAndOrderFront];
//        [self.browserController.mainBrowserWindow makeContentFirstResponder];
        DDLogDebug(@"Active window: %@", NSApp.mainWindow);
//        NSAccessibilityPostNotification(self.browserController.mainBrowserWindow, NSAccessibilityFocusedWindowChangedNotification);
        
        if (NSApp.mainWindow) {
            NSDictionary *userInfo = @{
                NSAccessibilityUIElementsKey: @[NSApp.mainWindow],
                NSAccessibilityFocusedWindowAttribute: NSApp.mainWindow
            };
            NSAccessibilityPostNotificationWithUserInfo(NSApp.mainWindow, NSAccessibilityFocusedUIElementChangedNotification, userInfo);
        }
    }
}


- (void) appLaunch: (id)sender
{
#ifdef DEBUG
    DDLogInfo(@"%s: Notification:  %@", __FUNCTION__, [sender name]);
#endif
    
    if ([[sender name] isEqualToString:@"NSWorkspaceDidLaunchApplicationNotification"]) {
        NSDictionary *userInfo = [sender userInfo];
        if (userInfo) {
            // Save the information which app was started
            launchedApplication = [userInfo objectForKey:NSWorkspaceApplicationKey];
            NSString *launchedAppBundleID = launchedApplication.bundleIdentifier;
            DDLogInfo(@"launched app localizedName: %@, bundleID: %@ executableURL: %@", [launchedApplication localizedName], launchedAppBundleID, [launchedApplication executableURL]);
        }
    }
}


- (void) spaceSwitch: (id)sender
{
#ifdef DEBUG
    DDLogInfo(@"%s: Notification:  %@", __FUNCTION__, [sender name]);
#endif
    
    NSDictionary *userInfo = [sender userInfo];
    NSRunningApplication *workspaceSwitchingApp;
    if (userInfo) {
        workspaceSwitchingApp = [userInfo objectForKey:NSWorkspaceApplicationKey];
        DDLogInfo(@"App which switched Space localized name: %@, executable URL: %@", [workspaceSwitchingApp localizedName], [workspaceSwitchingApp executableURL]);
    }
    // #100: ANY transition into a full-screen Space while the kiosk should own the screen is a
    // bypass in progress, whoever caused it. The branch below only ever fired for an app that
    // LAUNCHED after SEB started, which a pre-existing full-screen app never does — and this also
    // covers the child swiping back to the Space by gesture, which was never established as being
    // blocked and must not be assumed to be. Rate-limited inside, so it cannot ping-pong.
    [self blinkeredEnsureOrdinarySpace:@"space-changed"];
    // If an app was started since SEB was running
    if (_isAACEnabled == NO && _wasAACEnabled == NO && launchedApplication && ![launchedApplication isEqual:[NSRunningApplication currentApplication]]) {
        // Yes: We assume it's the app which switched the space and force terminate it!
        DDLogError(@"An app was started and switched the Space. SEB will force terminate it! (app localized name: %@, executable URL: %@)", [launchedApplication localizedName], [launchedApplication executableURL]);
        
        DDLogDebug(@"Reinforcing the kiosk mode was requested");
        // Switch the strict kiosk mode temporarily off
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        [preferences setSecureBool:NO forKey:@"org_safeexambrowser_elevateWindowLevels"];
        [self switchKioskModeAppsAllowed:YES overrideShowMenuBar:NO];
        
        // Close the black background covering windows
        [self closeCapWindows];
        
        [self killApplication:launchedApplication];
        launchedApplication = nil;

        // Reopen the covering Windows and reset the windows elevation levels
        DDLogDebug(@"requestedReinforceKioskMode: Reopening cap windows.");
        [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
        if (self.browserController.mainBrowserWindow.isVisible) {
            [self.browserController.mainBrowserWindow makeKeyAndOrderFront:self];
        }
        
        // Open new covering background windows on all currently available screens
        [preferences setSecureBool:NO forKey:@"org_safeexambrowser_elevateWindowLevels"];
        [self coverScreens];
        
        // Switch the proper kiosk mode on again
        [self setElevateWindowLevels];
        
        [self switchKioskModeAppsAllowed:_sessionState.allowSwitchToApplications overrideShowMenuBar:NO];
        
        [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
        [self.browserController.mainBrowserWindow makeKeyAndOrderFront:self];

        if (NSApp.mainWindow) {
            NSDictionary *userInfo = @{
                NSAccessibilityUIElementsKey: @[NSApp.mainWindow],
                NSAccessibilityFocusedWindowAttribute: NSApp.mainWindow
            };
            NSAccessibilityPostNotificationWithUserInfo(NSApp.mainWindow, NSAccessibilityFocusedUIElementChangedNotification, userInfo);
        }
    }
}


- (BOOL) killApplication:(NSRunningApplication *)application
{
    NSString *appLocalizedName = application.localizedName;
    appLocalizedName = appLocalizedName ? appLocalizedName : application.executableURL.path;
    NSURL *appURL = [self getBundleOrExecutableURL:application];
    appURL = appURL ? appURL : NSURL.new;
    NSString *appBundleID = application.bundleIdentifier;
    appBundleID = appBundleID ? appBundleID : application.bundleURL.path;
    NSDictionary *processDetails = @{
        @"name" : appLocalizedName,
        @"PID" : [NSNumber numberWithInt:application.processIdentifier],
        @"URL": appURL,
        @"bundleID" : appBundleID
    };
    if (!self.sessionState.processCheckAllOverride && ![self isOverriddenProhibitedProcess:processDetails]) {
        BOOL killSuccess = [application kill];
        if (!killSuccess) {
            DDLogError(@"Couldn't terminate app with localized name (error %ld): %@, bundle or executable URL: %@", (long)killSuccess, appLocalizedName, appURL);
            [_runningProhibitedProcesses addObject:processDetails];
            [[NSNotificationCenter defaultCenter]
             postNotificationName:@"detectedProhibitedProcess" object:self];
        } else {
            if ([appBundleID isEqualToString:WebKitNetworkingProcessBundleID] || [appBundleID isEqualToString:UniversalControlBundleID]) {
                DDLogVerbose(@"Successfully terminated app with localized name: %@, bundle or executable URL: %@", appLocalizedName, appURL);
            } else {
                DDLogDebug(@"Successfully terminated app with localized name: %@, bundle or executable URL: %@", appLocalizedName, appURL);
            }
            if (appURL) {
                // Add the app's file URL, so we can restart it when exiting SEB
                [_terminatedProcessesExecutableURLs addObject:appURL];
            }
        }
        return killSuccess;
    } else {
        DDLogWarn(@"Didn't terminate app with localized name: %@, bundle or executable URL: %@, because a user did override it with the quit/unlock password.", appLocalizedName, appURL);
        return YES;
    }
}


- (NSError * _Nullable) killProcessWithPID:(pid_t)processPID
{
    NSString * processName = [self getProcessName:processPID];
    NSDictionary *processDetails = @{
        @"name" : processName,
        @"PID" : [NSNumber numberWithInt:processPID]
    };
    return [self killProcess:processDetails];
}


- (NSError * _Nullable) killProcess:(NSDictionary *)processDictionary
{
    NSNumber *PID = [processDictionary objectForKey:@"PID"];
    pid_t processPID = PID.intValue;
    
    NSRunningApplication *application = [NSRunningApplication runningApplicationWithProcessIdentifier:processPID];
    NSURL *appURL = processDictionary[@"URL"];
    NSMutableDictionary *processDetails = [NSMutableDictionary new];
    NSString *processName = processDictionary[@"name"];
    if (processName) {
        [processDetails setValue:processName forKey:@"name"];
    }
    if (application) {
        appURL = [self getBundleOrExecutableURL:application];
        [processDetails setValue:application.bundleIdentifier forKey:@"bundleID"];
    } else if (!appURL) {
        NSString *executablePath = [ProcessManager getExecutablePathForPID:processPID];
        if (executablePath) {
            appURL = [NSURL fileURLWithPath:executablePath isDirectory:NO];
        }
    }
    if (appURL) {
        [processDetails setValue:appURL forKey:@"URL"];
    }

    NSError *error = nil;
    if (!self.sessionState.processCheckAllOverride && ![self isOverriddenProhibitedProcess:processDetails]) {
        BOOL killSuccess = [NSRunningApplication killProcessWithPID:processPID error:&error];
        if (killSuccess) {
            DDLogDebug(@"Successfully terminated application/process: %@", processDetails);
            if (appURL) {
                [_terminatedProcessesExecutableURLs addObject:appURL];
            }
        } else {
            DDLogError(@"Couldn't terminate application/process: %@, error code: %ld", processDetails, (long)killSuccess);
            if (![_runningProhibitedProcesses containsObject:processDetails.copy]) {
                [_runningProhibitedProcesses addObject:processDetails.copy];
            }
            [[NSNotificationCenter defaultCenter]
             postNotificationName:@"detectedProhibitedProcess" object:self];
        }
    } else {
        DDLogWarn(@"Didn't terminate app with localized name '%@' or process with bundle or executable URL '%@', because a user did override it with the quit/unlock password.", application.localizedName, appURL);
    }
    return error;
}


- (BOOL) isOverriddenProhibitedProcess:(NSDictionary *)processDetails
{
    if (self.sessionState.overriddenProhibitedProcesses) {
        NSArray *filteredOverriddenProcesses = self.sessionState.overriddenProhibitedProcesses.copy;
        NSString *bundleID = processDetails[@"bundleID"];
        if (bundleID) {
            NSPredicate *processFilter = [NSPredicate predicateWithFormat:@"bundleID ==[cd] %@", bundleID];
            filteredOverriddenProcesses = [filteredOverriddenProcesses filteredArrayUsingPredicate:processFilter];
            if (filteredOverriddenProcesses.count == 0) {
                return NO;
            }
        }
        NSURL* processURL = processDetails[@"URL"];
        if (processURL) {
            NSPredicate *processFilter = [NSPredicate predicateWithFormat:@"URL ==[cd] %@", processURL];
            filteredOverriddenProcesses = [filteredOverriddenProcesses filteredArrayUsingPredicate:processFilter];
            if (filteredOverriddenProcesses.count == 0) {
                return NO;
            }
        }
        NSString *processName = processDetails[@"name"];
        NSPredicate *processFilter = [NSPredicate predicateWithFormat:@"name ==[cd] %@", processName];
        filteredOverriddenProcesses = [filteredOverriddenProcesses filteredArrayUsingPredicate:processFilter];
        if (filteredOverriddenProcesses.count != 0) {
            return YES;
        }
    }
    return NO;
}


- (void) SEBgotActive: (id)sender {
    DDLogDebug(@"SEB got active");
//    [self startKioskMode];
}


#pragma mark - Kiosk Mode

- (void) updateAACAvailablility
{
    NSUInteger currentOSMajorVersion = NSProcessInfo.processInfo.operatingSystemVersion.majorVersion;
    NSUInteger currentOSMinorVersion = NSProcessInfo.processInfo.operatingSystemVersion.minorVersion;
    NSUInteger currentOSPatchVersion = NSProcessInfo.processInfo.operatingSystemVersion.patchVersion;

    BOOL aacDnsPrePinning = [[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_aacDnsPrePinning"];
    // Determine on which macOS versions AAC is possible:
    BOOL aacPossible = ((currentOSMajorVersion == 10 && currentOSMinorVersion == 15 && currentOSPatchVersion >= 4) && //>= Catalina 10.15.4
    !(currentOSMajorVersion == 10 && currentOSMinorVersion == 15 && currentOSPatchVersion == 5)) || //except 10.15.5 connectivity broken
    (aacDnsPrePinning && currentOSMajorVersion == 11) || //Big Sur 11 with DNS pre-pinning
    (aacDnsPrePinning && currentOSMajorVersion == 12 && currentOSMinorVersion == 1) || //Monterey 12.1 with DNS pre-pinning
    (currentOSMajorVersion == 12 && currentOSMinorVersion > 1) || //>12.1 without bugs (hopefully)
    currentOSMajorVersion > 12;
    
    // Blinkered: AAC disabled — not needed for classroom use and requires special entitlement
    _isAACEnabled = NO;
    DDLogDebug(@"Updated _isAACEnabled to %d (_overrideAAC = %d)", _isAACEnabled, _overrideAAC);
}


// Method which sets the setting flag for elevating window levels according to the
// setting key allowSwitchToApplications
- (void) setElevateWindowLevels
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    _sessionState.allowSwitchToApplications = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowSwitchToApplications"];
    if (_sessionState.allowSwitchToApplications || _isAACEnabled || _wasAACEnabled) {
        DDLogDebug(@"%s: false", __FUNCTION__);
        [preferences setSecureBool:NO forKey:@"org_safeexambrowser_elevateWindowLevels"];
    } else {
        DDLogDebug(@"%s: true", __FUNCTION__);
        [preferences setSecureBool:YES forKey:@"org_safeexambrowser_elevateWindowLevels"];
    }
}


// ── Press-and-hold accent popover visibility in locked sessions ───────────────
// macOS shows the accent popover (à á â ä å ã, è é ê ë …) as an NSPanel at
// NSDockWindowLevel (20). When window levels are elevated for a locked session our
// browser windows sit at NSMainMenuWindowLevel+3/+4, so the popover is created BELOW
// them and stays hidden — holding a key appears to do nothing. We can't lower the
// browser window (it must stay above the menu bar and cap windows), so instead we
// detect the popover panel (it's our own in-process window) and raise it just above
// the browser window for the moment it's on screen. The panel is destroyed when the
// key is released, so this has no lasting effect on the lockdown, and the anti-overlay
// scanner ignores it because it belongs to our own process.

static NSTimer *_accentPopoverRaiseTimer = nil;
static NSDate *_accentPopoverRaiseDeadline = nil;

// Called from the keyDown monitor on each plain character key. Runs a short, self-
// expiring poll (the popover appears ~0.5 s into a hold and we re-raise it while held).
- (void) noteAccentPopoverActivity
{
    if (![[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_elevateWindowLevels"]) {
        return;     // Normal (non-elevated) windows show the popover natively — nothing to do.
    }
    // Keep watching for ~1.5 s after the last keystroke, covering the press-and-hold delay.
    _accentPopoverRaiseDeadline = [NSDate dateWithTimeIntervalSinceNow:1.5];
    if (!_accentPopoverRaiseTimer) {
        _accentPopoverRaiseTimer = [NSTimer scheduledTimerWithTimeInterval:0.1
                                                                    target:self
                                                                  selector:@selector(raiseAccentPopoverTick:)
                                                                  userInfo:nil
                                                                   repeats:YES];
    }
}

- (void) raiseAccentPopoverTick:(NSTimer *)timer
{
    if (!_accentPopoverRaiseDeadline || _accentPopoverRaiseDeadline.timeIntervalSinceNow < 0) {
        [_accentPopoverRaiseTimer invalidate];
        _accentPopoverRaiseTimer = nil;
        _accentPopoverRaiseDeadline = nil;
        return;
    }
    [self raiseAccentPopoverPanels];
}

- (void) raiseAccentPopoverPanels
{
    NSInteger dockLevel = CGWindowLevelForKey(kCGDockWindowLevelKey);   // == 20, where the popover lives
    // Raise it just above the focused browser window. keyWindow stays the browser window
    // (the popover panel doesn't become key); fall back to a safe high level otherwise.
    NSWindow *keyWindow = NSApp.keyWindow;
    NSInteger targetLevel = (keyWindow && keyWindow.level >= NSMainMenuWindowLevel)
                          ? keyWindow.level + 1
                          : NSMainMenuWindowLevel + 5;
    for (NSWindow *window in NSApp.windows) {
        if ([window isKindOfClass:[NSPanel class]] && window.level == dockLevel) {
            window.level = targetLevel;
        }
    }
}


- (void) startKioskMode {
    DDLogDebug(@"%s", __FUNCTION__);
	// Switch to kiosk mode by setting the proper presentation options
    // Load preferences from the system's user defaults database
//    [self startKioskModeThirdPartyAppsAllowed:YES];
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    BOOL allowSwitchToThirdPartyApps = ![preferences secureBoolForKey:@"org_safeexambrowser_elevateWindowLevels"];
    DDLogDebug(@"startKioskMode switchToApplications %hhd", allowSwitchToThirdPartyApps);
    [self startKioskModeThirdPartyAppsAllowed:allowSwitchToThirdPartyApps overrideShowMenuBar:NO];
    [self blinkeredStartSessionMarker];
}


// Blinkered: while a lockdown/focus session is active, drop a marker the root updater daemon
// (BlinkeredUpdater) checks so it never swaps the app bundle mid-session — see
// docs/ROOT_UPDATER_HELPER_PLAN.md. /Users/Shared is world-writable, so the child (a standard user)
// can write it and root can read it. We HEARTBEAT it every 10 min because a lock can outlast the
// daemon's 30-min staleness window; the marker is only ever a *defer* signal (never trusted for more).
static NSTimer *_blinkeredSessionMarkerTimer = nil;
static NSString * const kBlinkeredSessionMarkerPath = @"/Users/Shared/.blinkered-session.lock";

- (void)blinkeredTouchSessionMarker {
    // createFileAtPath overwrites an existing file, which refreshes its modification time (the heartbeat).
    [[NSFileManager defaultManager] createFileAtPath:kBlinkeredSessionMarkerPath contents:[NSData data] attributes:nil];
}

- (void)blinkeredStartSessionMarker {
    [self blinkeredTouchSessionMarker];
    [_blinkeredSessionMarkerTimer invalidate];
    __weak typeof(self) weakSelf = self;
    _blinkeredSessionMarkerTimer = [NSTimer scheduledTimerWithTimeInterval:600 repeats:YES block:^(NSTimer * _Nonnull timer) {
        [weakSelf blinkeredTouchSessionMarker];
    }];
    DDLogInfo(@"Blinkered: session update-defer marker written (heartbeating every 10 min)");
}

- (void)blinkeredStopSessionMarker {
    [_blinkeredSessionMarkerTimer invalidate];
    _blinkeredSessionMarkerTimer = nil;
    [[NSFileManager defaultManager] removeItemAtPath:kBlinkeredSessionMarkerPath error:NULL];
    DDLogInfo(@"Blinkered: session update-defer marker cleared");
}


// ── Blinkered menu-bar click shield ──────────────────────────────────────────────────────
// Active only while kiosk mode is elevated AND the menu bar is visible (home locks; any
// class config that shows the bar). Relaxed/settings flows pass allowApps:YES and exam
// configs hide the bar entirely, so both deactivate it naturally. See the
// BlinkeredMenuBarShieldView comment for what this exists to stop.
static NSMutableArray *_blinkeredMenuBarShieldWindows = nil;
static id _blinkeredMenuBarShieldScreenObserver = nil;

- (void)blinkeredSetMenuBarShieldActive:(BOOL)active
{
    if (!active) {
        if (_blinkeredMenuBarShieldWindows.count) {
            DDLogInfo(@"Blinkered: menu-bar click shield OFF");
            for (NSWindow *shieldWindow in _blinkeredMenuBarShieldWindows) {
                [shieldWindow orderOut:self];
            }
            [_blinkeredMenuBarShieldWindows removeAllObjects];
        }
        if (_blinkeredMenuBarShieldScreenObserver) {
            [[NSNotificationCenter defaultCenter] removeObserver:_blinkeredMenuBarShieldScreenObserver];
            _blinkeredMenuBarShieldScreenObserver = nil;
        }
        return;
    }
    if (!_blinkeredMenuBarShieldWindows) {
        _blinkeredMenuBarShieldWindows = [NSMutableArray new];
    }
    if (!_blinkeredMenuBarShieldScreenObserver) {
        __weak typeof(self) weakSelf = self;
        _blinkeredMenuBarShieldScreenObserver = [[NSNotificationCenter defaultCenter]
            addObserverForName:NSApplicationDidChangeScreenParametersNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note) {
            [weakSelf blinkeredLayoutMenuBarShieldWindows];
        }];
    }
    [self blinkeredLayoutMenuBarShieldWindows];
}

- (void)blinkeredLayoutMenuBarShieldWindows
{
    if (!_blinkeredMenuBarShieldWindows) {
        return; // shield not active
    }
    NSArray *screens = [NSScreen screens];
    // Adopt-in-place when the screen count matches (same reason as coverScreens: window
    // recreation animates visibly on macOS 26); rebuild the set only when it changed.
    if (_blinkeredMenuBarShieldWindows.count != screens.count) {
        for (NSWindow *shieldWindow in _blinkeredMenuBarShieldWindows) {
            [shieldWindow orderOut:self];
        }
        [_blinkeredMenuBarShieldWindows removeAllObjects];
        for (NSUInteger i = 0; i < screens.count; i++) {
            NSWindow *shieldWindow = [[NSWindow alloc] initWithContentRect:NSZeroRect
                                                                 styleMask:NSWindowStyleMaskBorderless
                                                                   backing:NSBackingStoreBuffered
                                                                     defer:NO];
            shieldWindow.releasedWhenClosed = NO;
            shieldWindow.opaque = NO;
            // 0.001 alpha: visually nothing, but the window server still hit-tests the strip
            // (a fully clear window would let clicks fall through to the status items).
            shieldWindow.backgroundColor = [NSColor colorWithCalibratedWhite:0 alpha:0.001];
            shieldWindow.hasShadow = NO;
            shieldWindow.animationBehavior = NSWindowAnimationBehaviorNone;
            shieldWindow.ignoresMouseEvents = NO;
            shieldWindow.collectionBehavior = NSWindowCollectionBehaviorCanJoinAllSpaces
                | NSWindowCollectionBehaviorStationary
                | NSWindowCollectionBehaviorFullScreenAuxiliary
                | NSWindowCollectionBehaviorIgnoresCycle;
            [shieldWindow setAccessibilityElement:NO];
            if ([NSUserDefaults standardUserDefaults].allowWindowCapture == NO) {
                [shieldWindow setSharingType:NSWindowSharingNone];
            }
            shieldWindow.contentView = [[BlinkeredMenuBarShieldView alloc] initWithFrame:NSZeroRect];
            [_blinkeredMenuBarShieldWindows addObject:shieldWindow];
        }
        DDLogInfo(@"Blinkered: menu-bar click shield ON (%lu screen(s))", (unsigned long)screens.count);
    }
    // Frame each shield over the RIGHT HALF of its screen's menu-bar strip, leveled above the
    // status items (status-item windows sit at NSStatusWindowLevel = NSMainMenuWindowLevel+1;
    // +2 matches the cap windows). setFrame: takes global coordinates, so derive from screen.frame.
    [_blinkeredMenuBarShieldWindows enumerateObjectsUsingBlock:^(NSWindow *shieldWindow, NSUInteger idx, BOOL *stop) {
        NSScreen *screen = screens[idx];
        // The menuBarHeight category subtracts 1 pt (the covers stop 1 pt short of the bar);
        // add it back so the shield covers the full strip including its bottom edge.
        CGFloat barHeight = screen.menuBarHeight + 1;
        NSRect frame = screen.frame;
        // Cover only the right half of the strip — the status-item region (the Microsoft Defender
        // shield that wedged a locked Mac, the Wi-Fi toggle's induced-offline attack, Control
        // Center, clock, battery: the click hazards, all right-aligned). The left half stays
        // clickable so the Apple menu (already OS-disabled under a home lock via
        // NSApplicationPresentationDisableAppleMenu) and the app menus (Blinkered/File/Edit/View/
        // Window) remain usable. On notched MacBooks the split lands at the notch, which already
        // separates the app menus (left of notch) from the status items (right of notch).
        frame.origin.x = NSMidX(screen.frame);
        frame.size.width = screen.frame.size.width / 2.0;
        frame.origin.y = NSMaxY(screen.frame) - barHeight;
        frame.size.height = barHeight;
        [shieldWindow setFrame:frame display:YES];
        [shieldWindow newSetLevel:NSMainMenuWindowLevel+2];
        [shieldWindow orderFrontRegardless];
    }];
}


- (void) switchKioskModeAppsAllowed:(BOOL)allowApps overrideShowMenuBar:(BOOL)overrideShowMenuBar
{
    DDLogDebug(@"%s allowApps: %hhd overrideShowMenuBar: %hhd", __FUNCTION__, allowApps, overrideShowMenuBar);
	// Switch the kiosk mode to either only browser windows or also third party apps allowed:
    // Change presentation options and windows levels without closing/reopening cap background and browser foreground windows
    [self startKioskModeThirdPartyAppsAllowed:allowApps overrideShowMenuBar:overrideShowMenuBar];
    [self changeWindowLevels:allowApps];
}


// Change window levels without closing/reopening cap background and browser foreground windows
- (void) changeWindowLevels:(BOOL)allowApps
{
    DDLogDebug(@"%s allowApps: %hhd", __FUNCTION__, allowApps);
    
    // Change window level of cap windows
    CapWindow *capWindow;
//    BOOL allowAppsUserDefaultsSetting = [[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_allowSwitchToApplications"];
    
    for (capWindow in self.capWindows) {
        if (allowApps || _isAACEnabled) {
            [capWindow newSetLevel:NSNormalWindowLevel];
            if (_sessionState.allowSwitchToApplications) {
                capWindow.collectionBehavior = NSWindowCollectionBehaviorStationary + NSWindowCollectionBehaviorFullScreenAuxiliary +NSWindowCollectionBehaviorFullScreenDisallowsTiling;
            }
        } else {
            [capWindow newSetLevel:NSMainMenuWindowLevel+2];
        }
    }
    
    // Change window level of all open browser windows
    [self.browserController browserWindowsChangeLevelAllowApps:allowApps];
    
    // Change window level of a modal window (like an alert) if one is displayed
    [self adjustModalAlertWindowLevels:_sessionState.allowSwitchToApplications];
    
    // Change window level of the about window if it is displayed
    if (self.aboutWindow.isVisible) {
        DDLogWarn(@"About window displayed");
        if (allowApps  || _isAACEnabled) {
            [self.aboutWindow newSetLevel:NSModalPanelWindowLevel-1];
        } else {
            [self.aboutWindow newSetLevel:NSMainMenuWindowLevel+5];
        }
    }
}


- (void) startKioskModeThirdPartyAppsAllowed:(BOOL)allowSwitchToThirdPartyApps overrideShowMenuBar:(BOOL)overrideShowMenuBar
{
    DDLogDebug(@"%s", __FUNCTION__);
    // The loaded settings drive window leveling from here on — the early
    // session-launch covers hand over to config-driven leveling.
    _blinkeredEarlyCoversActive = NO;
    // Switch to kiosk mode by setting the proper presentation options
    // Load preferences from the system's user defaults database
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    BOOL showMenuBar = overrideShowMenuBar || [preferences secureBoolForKey:@"org_safeexambrowser_SEB_showMenuBar"];
    NSApplicationPresentationOptions presentationOptions;
    
        if (allowSwitchToThirdPartyApps) {
            [preferences setSecureBool:NO forKey:@"org_safeexambrowser_elevateWindowLevels"];
        } else {
            [preferences setSecureBool:YES forKey:@"org_safeexambrowser_elevateWindowLevels"];
        }
        
        if (!allowSwitchToThirdPartyApps) {
            // if switching to third party apps not allowed
            presentationOptions =
            NSApplicationPresentationDisableAppleMenu +
            NSApplicationPresentationHideDock +
            (showMenuBar ? 0 : NSApplicationPresentationHideMenuBar) +
            NSApplicationPresentationDisableProcessSwitching +
            NSApplicationPresentationDisableForceQuit +
            NSApplicationPresentationDisableSessionTermination;
        } else {
            presentationOptions =
            (showMenuBar ? 0 : NSApplicationPresentationHideMenuBar) +
            NSApplicationPresentationHideDock +
            NSApplicationPresentationDisableAppleMenu +
            NSApplicationPresentationDisableForceQuit +
            NSApplicationPresentationDisableSessionTermination;
        }
    
    @try {
        [[MyGlobals sharedMyGlobals] setStartKioskChangedPresentationOptions:YES];
        
        DDLogDebug(@"NSApp setPresentationOptions: %lo", presentationOptions);
        
        [NSApp setPresentationOptions:presentationOptions];
        [[MyGlobals sharedMyGlobals] setPresentationOptions:presentationOptions];
    }
    @catch(NSException *exception) {
        DDLogError(@"Error.  Make sure you have a valid combination of presentation options.");
    }

        // Blinkered: with the bar visible in an elevated session, swallow all menu-bar clicks
        // (Defender-shield wedge + Wi-Fi-toggle induced-offline). Every kiosk start/switch/
        // reinforce funnels through here, so the shield always tracks the current mode.
        [self blinkeredSetMenuBarShieldActive:(showMenuBar && !allowSwitchToThirdPartyApps && !_isAACEnabled)];

        // Change window level of a modal window (like an alert) if one is displayed
        [self adjustModalAlertWindowLevels:allowSwitchToThirdPartyApps];
        
        // Change window level of the about window if it is displayed
        if (self.aboutWindow.isVisible) {
            DDLogWarn(@"About window displayed");
            if (allowSwitchToThirdPartyApps || _isAACEnabled) {
                [self.aboutWindow newSetLevel:NSModalPanelWindowLevel-1];
            } else {
                [self.aboutWindow newSetLevel:NSMainMenuWindowLevel+5];
            }
        }
    }


// Change window level of a modal window (like an alert) if one is displayed
- (void)adjustModalAlertWindowLevels:(BOOL)allowSwitchToThirdPartyApps
{
    DDLogDebug(@"%s allowSwitchToThirdPartyApps: %hhd", __FUNCTION__, allowSwitchToThirdPartyApps);

    if (_modalAlertWindows.count) {
        DDLogWarn(@"Modal window(s) displayed");
        for (NSWindow *alertWindow in _modalAlertWindows)
        {
            if (allowSwitchToThirdPartyApps || _isAACEnabled) {
                [alertWindow newSetLevel:NSModalPanelWindowLevel];
            } else {
                [alertWindow newSetLevel:NSMainMenuWindowLevel+6];
            }
        }
    }
}


- (void)requestedReinforceKioskMode:(NSNotification *)notification
{
    [self reinforceKioskMode];
}

- (void)reinforceKioskMode
{
    if (!self.settingsOpen) {
        DDLogDebug(@"Reinforcing the kiosk mode was requested");
        
        if (_isAACEnabled == NO && _wasAACEnabled == NO) {
            // Re-assert the kiosk mode directly: presentation options and window
            // levels are absolute, so the old "switch temporarily off, then back on"
            // dance added nothing except a brief window with relaxed lockdown and a
            // visible level dip of covers/splash/browser on every reinforce (which
            // fires twice during a normal session launch).
            DDLogDebug(@"requestedReinforceKioskMode: Re-asserting kiosk mode without the temporary off-switch.");
            [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
            if (self.browserController.mainBrowserWindow.isVisible) {
                [self.browserController.mainBrowserWindow makeKeyAndOrderFront:self];
            }

            // Re-cover all currently available screens (adopt-in-place, rebuild only
            // if the screen set changed)
            [self setElevateWindowLevels];
            [self coverScreens];

            [self switchKioskModeAppsAllowed:_sessionState.allowSwitchToApplications overrideShowMenuBar:NO];
            
            [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
            [self.browserController.mainBrowserWindow makeKeyAndOrderFront:self];
            
            if (NSApp.mainWindow) {
                NSDictionary *userInfo = @{
                    NSAccessibilityUIElementsKey: @[NSApp.mainWindow],
                    NSAccessibilityFocusedWindowAttribute: NSApp.mainWindow
                };
                NSAccessibilityPostNotificationWithUserInfo(NSApp.mainWindow, NSAccessibilityFocusedUIElementChangedNotification, userInfo);
            }
        }
        // Fullscreen kiosk windows must stay opted out of OS window management
        // (Window menu Center/Fill/tiling on macOS 15+ move any movable window).
        if (self.browserController.mainBrowserWindow.isFullScreen) {
            self.browserController.mainBrowserWindow.movable = NO;
        }
        [self.browserController.mainBrowserWindow setCalculatedFrame];
    }
}


#pragma mark - Handling Additional Apps



#pragma mark - Setup Main User Interface

- (IBAction) reload:(id)sender
{
    if (!(_screenProctoringController && _screenProctoringController.sessionIsClosing)) {
        [self reloadButtonPressed];
    }
}

// Customized cut, copy, paste Menu commands

- (IBAction) copy:(id)sender
{
    if (!self.settingsOpen) {
        [self.browserController privateCopy:sender];
    } else {
        [NSApp.keyWindow.firstResponder tryToPerform:@selector(copy:) with:sender];
    }
}


- (IBAction) cut:(id)sender
{
    if (!self.settingsOpen) {
        [self.browserController privateCut:sender];
    } else {
        [NSApp.keyWindow.firstResponder tryToPerform:@selector(cut:) with:sender];
    }
}


- (IBAction) paste:(id)sender
{
    if (!self.settingsOpen) {
        [self.browserController privatePaste:sender];
    } else {
        [NSApp.keyWindow.firstResponder tryToPerform:@selector(paste:) with:sender];
    }
}


// Find the real visible frame of a screen SEB is running on
- (NSRect) visibleFrameForScreen:(NSScreen *)screen
{
    if (!screen) {
        screen = self.browserController.mainBrowserWindow.screen;
    }
    // Get frame of the usable screen (considering if menu bar is enabled)
    NSRect screenFrame = screen.usableFrame;
    // Check if SEB Dock is displayed and reduce visibleFrame accordingly
    // Also check if mainBrowserWindow exists, because when starting with a temporary
    // browser window for loading a seb(s):// link from a authenticated server, there
    // is no main browser window open yet
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if ((!self.browserController.mainBrowserWindow || screen == self.browserController.mainBrowserWindow.screen) && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_showTaskBar"]) {
        double dockHeight = [preferences secureDoubleForKey:@"org_safeexambrowser_SEB_taskBarHeight"];
        screenFrame.origin.y += dockHeight;
        screenFrame.size.height -= dockHeight;
    }
    return screenFrame;
}


// Set up and display SEB Dock
- (void) openSEBDock
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if (self.dockController) {
        [self.dockController hideDock];
        self.dockController = nil;
    }

    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_showTaskBar"]) {
        
        DDLogDebug(@"SEBController openSEBDock: dock enabled");
        // Initialize the Dock
        SEBDockController *newDockController = [[SEBDockController alloc] init];
        self.dockController = newDockController;
        
        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_enableSebBrowser"]) {
            SEBDockItem *dockItemSEB = [[SEBDockItem alloc] initWithTitle:SEBFullAppNameClassic
                                                                 bundleID:nil
                                                         allowManualStart:NO
                                                                     icon:[NSImage imageNamed:@"AppIcon"]
                                                          highlightedIcon:[NSImage imageNamed:@"AppIcon"]
                                                                  toolTip:nil
                                                                     menu:self.browserController.openBrowserWindowsWebViewsMenu
                                                                   target:self
                                                                   action:@selector(sebButtonPressed)
                                                          secondaryAction:nil];
            NSArray *dockButtons = [self.dockController setLeftItems:[NSArray arrayWithObjects:dockItemSEB, nil]];
            [self setUpDockLeftButtons:dockButtons];
        }
        
        // Initialize center dock items (allowed third party applications)
        if (_isAACEnabled || _sessionState.allowSwitchToApplications) {
            NSMutableArray *centerDockItems = [NSMutableArray array];
            NSArray *permittedProcesses = [ProcessManager sharedProcessManager].permittedProcesses;
            DDLogDebug(@"%@%@ enabled: Check if there are permitted apps: %@", _isAACEnabled ? @"AAC" : @"", _sessionState.allowSwitchToApplications ? @"Switching to applications" : @"", permittedProcesses);
            for (NSDictionary *permittedProcess in permittedProcesses) {
                if ([permittedProcess[@"iconInTaskbar"] boolValue] == YES) {
                    NSString *appName = permittedProcess[@"title"];
                    NSString *appBundleID = permittedProcess[@"identifier"];
                    if (appName.length == 0) {
                        appName = permittedProcess[@"executable"];
                    }
                    if (appName.length == 0) {
                        appName = appBundleID;
                    }
                    BOOL allowManualStart = [permittedProcess[@"allowManualStart"] boolValue];
                    NSImage *appIcon = [[NSWorkspace sharedWorkspace] iconForFile:[[NSWorkspace sharedWorkspace] absolutePathForAppBundleWithIdentifier:appBundleID]];

                    SEBDockItem *dockItemApp = [[SEBDockItem alloc] initWithTitle:appName
                                                                         bundleID:appBundleID
                                                                 allowManualStart:allowManualStart
                                                                             icon:appIcon
                                                                  highlightedIcon:appIcon
                                                                          toolTip:nil
                                                                             menu:nil
                                                                           target:self
                                                                           action:@selector(appButtonPressed:)
                                                                  secondaryAction:nil];
                    [centerDockItems addObject:dockItemApp];
                }
            }
            if (centerDockItems.count > 0) {
                [self.dockController setCenterItems:centerDockItems.copy];
            }
        }
        
        // Initialize right dock items (controlls and info widgets)
        NSMutableArray *rightDockItems = [NSMutableArray array];
        
        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowQuit"] &&
            [preferences secureBoolForKey:@"org_safeexambrowser_SEB_showQuitButton"]) {
            SEBDockItem *dockItemShutDown = [[SEBDockItem alloc] initWithTitle:nil
                                                                      bundleID:nil
                                                              allowManualStart:NO
                                                                          icon:[NSImage imageNamed:@"SEBShutDownIcon"]
                                                               highlightedIcon:[NSImage imageNamed:@"SEBShutDownIconHighlighted"]
                                                                       toolTip:[NSString stringWithFormat:NSLocalizedString(@"Quit %@",nil), SEBShortAppName]
                                                                          menu:nil
                                                                        target:self
                                                                        action:@selector(quitButtonPressed)
                                                               secondaryAction:nil];
            [rightDockItems addObject:dockItemShutDown];
        }
        
        if (_isAACEnabled || ![preferences secureBoolForKey:@"org_safeexambrowser_SEB_showMenuBar"]) {
            SEBDockItemBattery *dockItemBattery = sebDockItemBattery;
            
            if ([dockItemBattery batteryLevel] != -1.0) {
                [dockItemBattery setToolTip:NSLocalizedString(@"Battery Status",nil)];
                [dockItemBattery startDisplayingBattery];
                [rightDockItems addObject:dockItemBattery];
                [self startBatteryMonitoringWithDelegate:dockItemBattery];
            }
        }

        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_enableScreenProctoring"]) {
            ScreenProctoringIconInactiveState = [NSImage imageNamed:@"SEBScreenProctoringIcon_inactive"];
            if (@available(macOS 10.14, *)) {
                ScreenProctoringIconActiveState = [NSImage imageNamed:@"SEBScreenProctoringIcon_active"];
                ScreenProctoringIconActiveWarningState = [NSImage imageNamed:@"SEBScreenProctoringIcon_active_warning"];
                ScreenProctoringIconActiveErrorState = [NSImage imageNamed:@"SEBScreenProctoringIcon_active_error"];
                ScreenProctoringIconInactiveErrorState = [NSImage imageNamed:@"SEBScreenProctoringIcon_inactive_error"];
            } else {
                ScreenProctoringIconActiveState = [NSImage imageNamed:@"SEBScreenProctoringIcon_active_green"];
                ScreenProctoringIconActiveWarningState = [NSImage imageNamed:@"SEBScreenProctoringIcon_active_warning_orange"];
                ScreenProctoringIconActiveErrorState = [NSImage imageNamed:@"SEBScreenProctoringIcon_active_error_red"];
                ScreenProctoringIconInactiveErrorState = [NSImage imageNamed:@"SEBScreenProctoringIcon_inactive_error_red"];

            }
            ScreenProctoringIconColorActiveState = [NSColor systemGreenColor];
            ScreenProctoringIconColorWarningState = [NSColor systemOrangeColor];
            ScreenProctoringIconColorErrorState = [NSColor systemRedColor];

            SEBDockItem *dockItemProctoringView = [[SEBDockItem alloc] initWithTitle:nil
                                                                            bundleID:nil
                                                                    allowManualStart:NO
                                                                          icon:ScreenProctoringIconInactiveState
                                                               highlightedIcon:ScreenProctoringIconInactiveState
                                                                       toolTip:NSLocalizedString(@"Screen Proctoring Inactive",nil)
                                                                          menu:nil
                                                                        target:self
                                                                        action:@selector(screenProctoringButtonAction)
                                                                     secondaryAction:nil];
            [rightDockItems addObject:dockItemProctoringView];
        }
        
        if (ZoomProctoringSupported && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_zoomEnable"]) {
            ProctoringIconDefaultState = [NSImage imageNamed:@"SEBProctoringViewIcon"];
//            ProctoringIconDefaultState.template = YES;
            ProctoringIconAIInactiveState = [NSImage imageNamed:@"SEBProctoringViewIcon_green"];
            ProctoringIconNormalState = [NSImage imageNamed:@"SEBProctoringViewIcon_checkmark"];
            ProctoringIconColorNormalState = [NSColor systemGreenColor];
//            ProctoringBadgeNormalState = [[CIImage alloc] initWithCGImage:[UIImage imageNamed:@"SEBBadgeCheckmark"].CGImage];
            ProctoringIconWarningState = [NSImage imageNamed:@"SEBProctoringViewIcon_warning"];
            ProctoringIconColorWarningState = [NSColor systemOrangeColor];
//            ProctoringBadgeWarningState = [[CIImage alloc] initWithCGImage:[UIImage imageNamed:@"SEBBadgeWarning"].CGImage];
            ProctoringIconErrorState = [NSImage imageNamed:@"SEBProctoringViewIcon_error"];
            ProctoringIconColorErrorState = [NSColor systemRedColor];
//            ProctoringBadgeErrorState = [[CIImage alloc] initWithCGImage:[UIImage imageNamed:@"SEBBadgeError"].CGImage];

            NSUInteger remoteProctoringViewShowPolicy = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_remoteProctoringViewShow"];
            BOOL allowToggleProctoringView = (remoteProctoringViewShowPolicy == remoteProctoringViewShowAllowToHide ||
                                              remoteProctoringViewShowPolicy == remoteProctoringViewShowAllowToShow);

            SEBDockItem *dockItemProctoringView = [[SEBDockItem alloc] initWithTitle:nil
                                                                            bundleID:nil
                                                                    allowManualStart:NO
                                                                          icon:[NSImage imageNamed:@"SEBProctoringViewIcon"]
                                                               highlightedIcon:[NSImage imageNamed:@"SEBProctoringViewIcon"]
                                                                       toolTip:allowToggleProctoringView ?
                                                   NSLocalizedString(@"Toggle Proctoring View",nil) :
                                                   NSLocalizedString(@"Remote Proctoring",nil)
                                                                          menu:nil
                                                                        target:self
                                                                        action:@selector(toggleProctoringViewVisibility)
                                                                     secondaryAction:nil];
            [rightDockItems addObject:dockItemProctoringView];
        }
        
        if (([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_sebMode"] == sebModeSebServer ||
            _establishingSEBServerConnection || _sebServerConnectionEstablished) &&
            [preferences secureBoolForKey:@"org_safeexambrowser_SEB_raiseHandButtonShow"]) {
            RaisedHandIconDefaultState = [NSImage imageNamed:@"SEBRaiseHandIcon"];
            RaisedHandIconColorDefaultState = nil;
//            RaisedHandIconDefaultState.template = YES;
            if (@available(macOS 10.14, *)) {
                RaisedHandIconRaisedState = [NSImage imageNamed:@"SEBRaiseHandIcon_raised"];
                RaisedHandIconRaisedState.template = YES;
                RaisedHandIconColorRaisedState = [NSColor systemYellowColor];
            } else {
                RaisedHandIconRaisedState = [NSImage imageNamed:@"SEBRaiseHandIcon_raised_yellow"];
            }
            SEBDockItem *dockItemRaiseHand = [[SEBDockItem alloc] initWithTitle:nil
                                                                       bundleID:nil
                                                               allowManualStart:NO
                                                                          icon:[NSImage imageNamed:@"SEBRaiseHandIcon"]
                                                               highlightedIcon:[NSImage imageNamed:@"SEBRaiseHandIcon"]
                                                                       toolTip:NSLocalizedString(@"Raise Hand",nil)
                                                                          menu:nil
                                                                        target:self
                                                                         action:@selector(toggleRaiseHand)
                                                                secondaryAction:@selector(showEnterRaiseHandMessageWindow)];
            [rightDockItems addObject:dockItemRaiseHand];
        }
        
        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_enableSebBrowser"] &&
            [preferences secureBoolForKey:@"org_safeexambrowser_SEB_showBackToStartButton"] &&
            ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_restartExamUseStartURL"] ||
            [preferences secureStringForKey:@"org_safeexambrowser_SEB_restartExamURL"].length > 0)) {
            NSString *restartButtonToolTip = [preferences secureStringForKey:@"org_safeexambrowser_SEB_restartExamText"];
            if (restartButtonToolTip.length == 0) {
                restartButtonToolTip = NSLocalizedString(@"Back to Start",nil);
            }
            SEBDockItem *dockItemSkipBack = [[SEBDockItem alloc] initWithTitle:nil
                                                                      bundleID:nil
                                                              allowManualStart:NO
                                                                          icon:[NSImage imageNamed:@"SEBSkipBackIcon"]
                                                               highlightedIcon:[NSImage imageNamed:@"SEBSkipBackIconHighlighted"]
                                                                       toolTip:restartButtonToolTip
                                                                          menu:nil
                                                                        target:self
                                                                        action:@selector(restartButtonPressed)
                                                               secondaryAction:nil];
            [rightDockItems addObject:dockItemSkipBack];
        }
        
        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_enableSebBrowser"] &&
            ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_browserWindowAllowReload"] ||
             [preferences secureBoolForKey:@"org_safeexambrowser_SEB_newBrowserWindowAllowReload"]) &&
            [preferences secureBoolForKey:@"org_safeexambrowser_SEB_showReloadButton"]) {
            SEBDockItem *dockItemReload = [[SEBDockItem alloc] initWithTitle:nil
                                                                    bundleID:nil
                                                            allowManualStart:NO
                                                                          icon:[NSImage imageNamed:@"SEBReloadIcon"]
                                                               highlightedIcon:[NSImage imageNamed:@"SEBReloadIconHighlighted"]
                                                                       toolTip:NSLocalizedString(@"Reload Current Page",nil)
                                                                          menu:nil
                                                                        target:self
                                                                        action:@selector(reloadButtonPressed)
                                                             secondaryAction:nil];
            [rightDockItems addObject:dockItemReload];
        }
        
        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_showTime"]) {
            SEBDockItemTime *dockItemTime = sebDockItemTime;
            [dockItemTime startDisplayingTime];
            
            [rightDockItems addObject:dockItemTime];
        }
        
        // Set right dock items
        NSArray *dockButtons = [self.dockController setRightItems:rightDockItems];
        [self setUpDockRightButtons:dockButtons];
        
        // Display the dock
        [self.dockController showDockOnScreen:_mainScreen];

    } else {
        DDLogDebug(@"SEBController openSEBDock: dock disabled");
    }
}


- (void)setUpDockLeftButtons: (NSArray *)dockButtons
{
    for (SEBDockItemButton *dockButton in dockButtons) {
        if (dockButton.action == @selector(sebButtonPressed)) {
            dockButton.accessibilityTitle = [NSString stringWithFormat:NSLocalizedString(@"Activates %@ browser. Right click displays menu with open webpages.", @""), SEBShortAppName];
        }
    }
}


- (void)setUpDockRightButtons: (NSArray *)dockButtons
{
    for (SEBDockItemButton *dockButton in dockButtons) {
        if (dockButton.action == @selector(reloadButtonPressed)) {
            _dockButtonReload = dockButton;
        }
        else if (dockButton.action == @selector(screenProctoringButtonAction)) {
            _dockButtonScreenProctoring = dockButton;
            _dockButtonScreenProctoring.image.template = YES;
            _dockButtonScreenProctoring.bezelStyle = NSBezelStyleInline;
            _dockButtonScreenProctoring.bordered = NO;
        }
        else if (dockButton.action == @selector(toggleProctoringViewVisibility)) {
            _dockButtonProctoringView = dockButton;
            _dockButtonProctoringView.image.template = YES;
            _dockButtonProctoringView.bezelStyle = NSBezelStyleInline;
            _dockButtonProctoringView.bordered = NO;
        }
        else if (dockButton.action == @selector(toggleRaiseHand)) {
            _dockButtonRaiseHand = dockButton;
            _dockButtonRaiseHand.image.template = YES;
            _dockButtonRaiseHand.bezelStyle = NSBezelStyleInline;
            _dockButtonRaiseHand.bordered = NO;
        }
    }
}


- (void) sebButtonPressed
{
    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    [self.browserController.mainBrowserWindow makeKeyAndOrderFront:self];
    
    if (NSApp.mainWindow) {
        NSDictionary *userInfo = @{
            NSAccessibilityUIElementsKey: @[NSApp.mainWindow],
            NSAccessibilityFocusedWindowAttribute: NSApp.mainWindow
        };
        NSAccessibilityPostNotificationWithUserInfo(NSApp.mainWindow, NSAccessibilityFocusedUIElementChangedNotification, userInfo);
    }
}


- (void) appButtonPressed:(id)sender
{
    SEBDockItemButton *appButton = (SEBDockItemButton *)sender;
    NSString *bundleID = appButton.bundleID;
    DDLogInfo(@"Dock button pressed for app: %@", bundleID);
    NSURL *appURL = [[NSWorkspace sharedWorkspace] URLForApplicationWithBundleIdentifier:bundleID];
    NSArray<NSRunningApplication *> *applicationInstances = [NSRunningApplication runningApplicationsWithBundleIdentifier: bundleID];
    if (applicationInstances.count == 1) {
        DDLogInfo(@"Application with Bundle ID %@ (%@) was already running", bundleID, applicationInstances[0]);
        BOOL activationSuccess = [applicationInstances[0] activateWithOptions:NSApplicationActivateAllWindows];
        DDLogInfo(@"Activating application %@ was %@successful", applicationInstances[0], activationSuccess ? @"" : @"not ");
    } else {
        if (appButton.allowManualStart == YES) {
            if (@available(macOS 10.15, *)) {
                NSWorkspaceOpenConfiguration *openConfiguration = [NSWorkspaceOpenConfiguration new];
                openConfiguration.activates = YES;
                openConfiguration.addsToRecentItems = NO;
                openConfiguration.allowsRunningApplicationSubstitution = NO;
                [[NSWorkspace sharedWorkspace] openApplicationAtURL:appURL configuration:openConfiguration completionHandler:^(NSRunningApplication * _Nullable app, NSError * _Nullable error) {
                    if (error) {
                        DDLogError(@"Application with Bundle ID %@ at %@ couldn't be opened with error %@", bundleID, appURL, error);
                    } else {
                        DDLogInfo(@"Application with Bundle ID %@ at %@ was opened successfully.", bundleID, appURL);
                    }
                }];
            }
        } else {
            // Manual start not allowed, show alert (TODO)
            DDLogInfo(@"Manually starting application with Bundle ID %@ at %@ is not allowed in current settings.", bundleID, appURL);
        }
    }
}


- (void) restartButtonPressed
{
    // Get custom (if it was set) or standard restart exam text
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    NSString *restartExamText = [preferences secureStringForKey:@"org_safeexambrowser_SEB_restartExamText"];
    if (restartExamText.length == 0) {
        restartExamText = NSLocalizedString(@"Back to Start",nil);
    }
    
    // Check if restarting is protected with the quit/unlock password (and one is set)
    NSString *hashedQuitPassword = [preferences secureObjectForKey:@"org_safeexambrowser_SEB_hashedQuitPassword"];
    
    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_restartExamPasswordProtected"] && ![hashedQuitPassword isEqualToString:@""])
    {
        // if quit/unlock password is set, then restrict quitting
        NSMutableParagraphStyle *textParagraph = [[NSMutableParagraphStyle alloc] init];
        textParagraph.lineSpacing = 5.0;
        NSMutableAttributedString *dialogText = [[NSAttributedString alloc] initWithString:[NSString stringWithFormat:@"%@\n", NSLocalizedString(@"Enter quit/unlock password:",nil)] attributes:@{NSFontAttributeName:[NSFont systemFontOfSize:NSFont.systemFontSize], NSParagraphStyleAttributeName:textParagraph}].mutableCopy;
        
        NSAttributedString *information = [[NSAttributedString alloc] initWithString:NSLocalizedString(@"(This function doesn't log you out if you are logged in on a website)", @"") attributes:@{NSFontAttributeName:[NSFont systemFontOfSize:NSFont.smallSystemFontSize]}];
        [dialogText appendAttributedString:information];
        
        if ([self showEnterPasswordDialogAttributedText:dialogText.copy
                                         modalForWindow:self.browserController.mainBrowserWindow
                                            pseudoModal:NO
                                            windowTitle:restartExamText] == SEBEnterPasswordCancel) {
            return;
        }
        NSString *password = [self.enterPassword stringValue];
        
        SEBKeychainManager *keychainManager = [[SEBKeychainManager alloc] init];
        if (hashedQuitPassword && [hashedQuitPassword caseInsensitiveCompare:[keychainManager generateSHAHashString:password]] == NSOrderedSame) {
            // if the correct quit/unlock password was entered, restart the exam
            [self.browserController backToStartCommand];
        } else {
            // Wrong quit password was entered
            NSAlert *modalAlert = [self newAlert];
            [modalAlert setMessageText:restartExamText];
            [modalAlert setInformativeText:NSLocalizedString(@"Wrong quit/unlock password.", @"")];
            [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
            [modalAlert setAlertStyle:NSAlertStyleCritical];
            void (^backToStartButtonOK)(NSModalResponse) = ^void (NSModalResponse answer) {
                [self removeAlertWindow:modalAlert.window];
            };
            [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))backToStartButtonOK];
        };
    } else {
        // If no quit password is required, then confirm quitting
        NSAlert *modalAlert = [self newAlert];
        [modalAlert setMessageText:restartExamText];
        [modalAlert setInformativeText:[NSString stringWithFormat:@"%@\n\n%@",
                                        NSLocalizedString(@"Are you sure?", @""),
                                        NSLocalizedString(@"(This function doesn't log you out if you are logged in on a website)", @"")
                                        ]];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
        [modalAlert setAlertStyle:NSAlertStyleWarning];
        void (^backToStartConfirmed)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self removeAlertWindow:modalAlert.window];
            switch(answer)
            {
                case NSAlertFirstButtonReturn:
                    return; //Cancel: don't restart exam
                default:
                    DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld. Not invoking Back to Start.", (long)answer);
                case NSAlertSecondButtonReturn:
                {
                    [self.browserController backToStartCommand];
                }
            }
        };
        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))backToStartConfirmed];
    }
}


- (void) reloadButtonPressed
{
    [self.browserController reloadCommand];
}


- (void) setReloadButtonEnabled:(BOOL)enabled
{
    _reloadPageUIElement.enabled = enabled;
}


- (void) batteryButtonPressed
{
    
}


- (void) quitButtonPressed
{
    // Post a notification that SEB should conditionally quit
    [[NSNotificationCenter defaultCenter]
     postNotificationName:@"requestQuitNotification" object:self];
}


- (IBAction) searchText:(id)sender
{
    [self.browserController.activeBrowserWindow searchText];
}

- (IBAction) searchTextNext:(id)sender
{
    [self.browserController.activeBrowserWindow searchTextNext];
}

- (IBAction) searchTextPrevious:(id)sender
{
    [self.browserController.activeBrowserWindow searchTextPrevious];
}


- (void) openURLs:(NSArray<NSURL *> *)urls withAppAtURL:(NSURL *)appURL bundleID:(NSString *)bundleID
{
    if (@available(macOS 10.15, *)) {
        if (!appURL) {
            appURL = [[NSWorkspace sharedWorkspace] URLForApplicationWithBundleIdentifier:bundleID];
        }
        if (appURL) {
            NSWorkspaceOpenConfiguration *openConfiguration = [NSWorkspaceOpenConfiguration new];
            openConfiguration.activates = YES;
            openConfiguration.addsToRecentItems = NO;
            openConfiguration.allowsRunningApplicationSubstitution = NO;
            if (urls.count > 0) {
                [[NSWorkspace sharedWorkspace] openURLs:urls withApplicationAtURL:appURL configuration:openConfiguration completionHandler:^(NSRunningApplication * _Nullable app, NSError * _Nullable error) {
                    if (error) {
                        DDLogError(@"URLs %@ couldn't be opened with application Bundle ID %@ at %@! Error: %@", urls, bundleID, appURL, error);
                    } else {
                        DDLogInfo(@"URLs %@ were opened successfully with application Bundle ID %@ at %@.", urls, bundleID, appURL);
                    }
                }];
            } else {
                [[NSWorkspace sharedWorkspace] openApplicationAtURL:appURL configuration:openConfiguration completionHandler:^(NSRunningApplication * _Nullable app, NSError * _Nullable error) {
                    if (error) {
                        DDLogError(@"Application with Bundle ID %@ at %@ couldn't be opened with error %@", bundleID, appURL, error);
                    } else {
                        DDLogInfo(@"Application with Bundle ID %@ at %@ was opened successfully.", bundleID, appURL);
                    }
                }];
            }
        }
    }
}


- (NSModalResponse) showEnterPasswordDialog:(NSString *)text 
                             modalForWindow:(NSWindow *_Nullable)window
                                pseudoModal:(BOOL)pseudoModal
                                windowTitle:(NSString *)title
{
    NSAttributedString *attributedText = [[NSAttributedString alloc] initWithString:text attributes:@{NSFontAttributeName:[NSFont systemFontOfSize:NSFont.systemFontSize]}];
    return [self showEnterPasswordDialogAttributedText:attributedText modalForWindow:window pseudoModal:pseudoModal windowTitle:title];
}
    
    
- (NSModalResponse) showEnterPasswordDialogAttributedText:(NSAttributedString *)text 
                                           modalForWindow:(NSWindow *)window
                                              pseudoModal:(BOOL)pseudoModal
                                              windowTitle:(NSString *)title
{
    [self.enterPassword setStringValue:@""]; //reset the enterPassword NSSecureTextField

    // Give the password prompt a cleaner look than the cramped default: a rounded,
    // larger field with a focus ring, in a roomier window. Idempotent — safe to run
    // each time the dialog is shown.
    self.enterPassword.bezelStyle = NSTextFieldRoundedBezel;
    self.enterPassword.font = [NSFont systemFontOfSize:15];
    self.enterPassword.focusRingType = NSFocusRingTypeDefault;
    if (enterPasswordDialogWindow) {
        NSRect frame = enterPasswordDialogWindow.frame;
        // Widen and slightly heighten the cramped default, keeping it centred as it
        // grows (the field is pinned to the window edges, so it grows with it).
        if (frame.size.width < 440.0) {
            CGFloat dw = 440.0 - frame.size.width;
            frame.size.width = 440.0;
            frame.origin.x -= dw / 2.0;
        }
        if (frame.size.height < 124.0) {
            CGFloat dh = 124.0 - frame.size.height;
            frame.size.height = 124.0;
            frame.origin.y -= dh / 2.0;
        }
        [enterPasswordDialogWindow setFrame:frame display:NO];
    }

    // If the (main) browser window is full screen, we don't show the dialog as sheet
    if (window == self.browserController.mainBrowserWindow && self.browserController.mainBrowserWindow.isFullScreen) {
        DDLogDebug(@"%s Not showing the dialog on a full screen browser window", __FUNCTION__);
        window = nil;
    }
    
    if (@available(macOS 12.0, *)) {
    } else {
        if (@available(macOS 11.0, *)) {
            if (!window && (_isAACEnabled || _wasAACEnabled)) {
                window = self.browserController.mainBrowserWindow;
            }
        }
    }

    // If the dialog needs to be shown application modal
    if (!window) {
        // block opening other modal alerts while the password dialog is open
        [_modalAlertWindows addObject:enterPasswordDialogWindow];
    }
    
    // Add the alert title string to the dialog text if the alert will be presented as sheet on a window
    if (window && title.length > 0) {
        NSMutableParagraphStyle *textParagraph = [[NSMutableParagraphStyle alloc] init];
        textParagraph.lineSpacing = 5.0;
        NSMutableAttributedString *dialogText = [[NSAttributedString alloc] initWithString:
                                                 [NSString stringWithFormat:@"%@\n", title]
                                                                                attributes:@{NSFontAttributeName:[NSFont boldSystemFontOfSize:NSFont.systemFontSize], NSParagraphStyleAttributeName:textParagraph}].mutableCopy;
        
        [dialogText appendAttributedString:text];
        text = dialogText.copy;
    } else if (title) {
        enterPasswordDialogWindow.title = title;
    }
    [enterPasswordDialog setAttributedStringValue:text];
    
    NSInteger returnCode = NSModalResponseCancel;
    if (!pseudoModal) {
        _pseudoModalWindow = NO;
        // The password prompt must never end up behind the cover windows (the early
        // session-launch covers are up before kiosk alert leveling applies).
        if (self.capWindows.count > 0 && !window) {
            [enterPasswordDialogWindow newSetLevel:NSMainMenuWindowLevel+6];
        }
        NSWindow *windowToShowModalFor;
        if (@available(macOS 12.0, *)) {
        } else {
            if (@available(macOS 11.0, *)) {
                windowToShowModalFor = window;
            }
        }
        [NSApp beginSheet: enterPasswordDialogWindow
           modalForWindow: windowToShowModalFor
            modalDelegate: nil
           didEndSelector: nil
              contextInfo: nil];
        returnCode = [NSApp runModalForWindow: enterPasswordDialogWindow];
        // Dialog is up here.
        [NSApp endSheet: enterPasswordDialogWindow];
        [enterPasswordDialogWindow orderOut: self];
        [self removeAlertWindow:enterPasswordDialogWindow];
    } else {
        _pseudoModalWindow = YES;
        [enterPasswordDialogWindow setLevel:NSScreenSaverWindowLevel+2];
        NSWindowController *windowController = [[NSWindowController alloc] initWithWindow:enterPasswordDialogWindow];
        [windowController showWindow:nil];
        returnCode = SEBEnterPasswordCancel;
    }
    return returnCode;
}

- (void) showEnterPasswordDialogClose
{
    NSString *password = [self.enterPassword stringValue];
    SEBKeychainManager *keychainManager = [[SEBKeychainManager alloc] init];
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    NSString *hashedQuitPassword = [preferences secureObjectForKey:@"org_safeexambrowser_SEB_hashedQuitPassword"];
    if (hashedQuitPassword && [hashedQuitPassword caseInsensitiveCompare:[keychainManager generateSHAHashString:password]] == NSOrderedSame) {
        // if the correct quit password was entered
        DDLogInfo(@"Correct quit password entered");
        [self exitSEB]; // Force quit SEB
    }
}


- (IBAction) okEnterPassword: (id)sender {
    if (!self.pseudoModalWindow) {
        [NSApp stopModalWithCode:SEBEnterPasswordOK];
    } else {
        [self showEnterPasswordDialogClose];
    }
}


- (IBAction) cancelEnterPassword: (id)sender {
    [NSApp stopModalWithCode:SEBEnterPasswordCancel];
    [enterPasswordDialogWindow orderOut: self];
    [self.enterPassword setStringValue:@""];
}


- (void) showEnterUsernamePasswordDialog:(NSString *)text
                          modalForWindow:(NSWindow *)window
                             windowTitle:(NSString *)title
                                username:(NSString *)username
                           modalDelegate:(id)modalDelegate
                          didEndSelector:(SEL)didEndSelector
{
    // Remember the delegate and selector of the sender
    senderModalDelegate = modalDelegate;
    senderDidEndSelector = didEndSelector;
    
    // Preset (or clear) the username field
    [usernameTextField setStringValue:username];
    // Reset the password field
    [passwordSecureTextField setStringValue:@""];
    
    // If there isn't a preset username (from a previous, failed attempt), move cursor
    // to the username field, otherwise to the password field
    if (username.length == 0) {
        [enterUsernamePasswordDialogWindow makeFirstResponder:usernameTextField];
    } else {
        [enterUsernamePasswordDialogWindow makeFirstResponder:passwordSecureTextField];
    }
    if (title) enterUsernamePasswordDialogWindow.title = title;
    [enterUsernamePasswordText setStringValue:text];
    
    // If the (main) browser window is full screen, we don't show the dialog as sheet
    if (window && (self.browserController.mainBrowserWindow.isFullScreen || self.settingsOpen)) {
        window = nil;
    }
    
    // If the dialog needs to be shown application modal
    if (!window) {
        // Add password dialog to open modal alerts
        [_modalAlertWindows addObject:enterPasswordDialogWindow];
    }
    
    if (@available(macOS 12.0, *)) {
    } else {
        if (@available(macOS 11.0, *)) {
            if (!window && (_isAACEnabled || _wasAACEnabled)) {
                window = self.browserController.mainBrowserWindow;
            }
        }
    }

    [NSApp beginSheet: enterUsernamePasswordDialogWindow
       modalForWindow: window
        modalDelegate: self
       didEndSelector: @selector(sheetDidEnd:returnCode:contextInfo:)
          contextInfo: nil];
}


- (IBAction) okEnterUsernamePassword: (id)sender {
    [NSApp endSheet:enterUsernamePasswordDialogWindow returnCode:SEBEnterPasswordOK];
    [self removeAlertWindow:enterPasswordDialogWindow];
}


- (IBAction) cancelEnterUsernamePassword: (id)sender {
    [NSApp endSheet:enterUsernamePasswordDialogWindow returnCode:SEBEnterPasswordCancel];
    // Reset the username field (password is always reset whenever the dialog is displayed)
    [usernameTextField setStringValue:@""];
    [self removeAlertWindow:enterPasswordDialogWindow];
}


- (void) hideEnterUsernamePasswordDialog
{
    [NSApp endSheet:enterUsernamePasswordDialogWindow returnCode:SEBEnterPasswordAborted];
    // Reset the user name field (password is always reset whenever the dialog is displayed)
    [usernameTextField setStringValue:@""];
    [self removeAlertWindow:enterPasswordDialogWindow];
}


- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(NSInteger)returnCode contextInfo:(void *)contextInfo
{
    DDLogDebug(@"sheetDidEnd with return code: %ld", (long)returnCode);
    
    [sheet orderOut: self];
    [self removeAlertWindow:enterPasswordDialogWindow];

    IMP imp = [senderModalDelegate methodForSelector:senderDidEndSelector];
    void (*func)(id, SEL, NSString*, NSString*, NSInteger) = (void *)imp;
    func(senderModalDelegate, senderDidEndSelector, usernameTextField.stringValue, passwordSecureTextField.stringValue, returnCode);
}


#pragma mark - Open/Close Preferences

- (BOOL) settingsOpen
{
    return [self.preferencesController preferencesAreOpen];
}


- (IBAction) openPreferences:(id)sender {
    if (!(_screenProctoringController && _screenProctoringController.sessionIsClosing)) {
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        if (lockdownWindows.count == 0 && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowPreferencesWindow"]) {
            [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
            if (!self.settingsOpen) {
                // Load admin password from the system's user defaults database
                NSString *hashedAdminPW = [preferences secureObjectForKey:@"org_safeexambrowser_SEB_hashedAdminPassword"];
                if (![hashedAdminPW isEqualToString:@""]) {
                    // If admin password is set, then restrict access to the preferences window
                    if ([self showEnterPasswordDialog:NSLocalizedString(@"Enter administrator password:",nil) modalForWindow:self.browserController.mainBrowserWindow pseudoModal:NO windowTitle:@""] == SEBEnterPasswordCancel) {
                        return;
                    }
                    NSString *password = [self.enterPassword stringValue];
                    SEBKeychainManager *keychainManager = [[SEBKeychainManager alloc] init];
                    if ([hashedAdminPW caseInsensitiveCompare:[keychainManager generateSHAHashString:password]] != NSOrderedSame) {
                        //if hash of entered password is not equal to the one in preferences
                        // Wrong admin password was entered
                        NSAlert *modalAlert = [self newAlert];
                        [modalAlert setMessageText:NSLocalizedString(@"Wrong Admin Password", @"")];
                        [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"If you don't enter the correct %@ administrator password, then you cannot open preferences.", @""), SEBShortAppName]];
                        [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                        [modalAlert setAlertStyle:NSAlertStyleWarning];
                        void (^wrongPasswordEnteredOK)(NSModalResponse) = ^void (NSModalResponse answer) {
                            [self removeAlertWindow:modalAlert.window];
                        };
                        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))wrongPasswordEnteredOK];
                        return;
                    }
                }
                if (_isAACEnabled == NO) {
                    // Switch the kiosk mode temporary off and override settings for menu bar: Show it while prefs are open
                    [preferences setSecureBool:NO forKey:@"org_safeexambrowser_elevateWindowLevels"];
                    [self switchKioskModeAppsAllowed:YES overrideShowMenuBar:YES];
                    // Close the black background covering windows
                    [self closeCapWindows];
                    // Show the Config menu (in menu bar)
                    [configMenu setHidden:NO];
                }
                
                // Check if the running prohibited processes window is open and close it if yes
                if (_processListViewController) {
                    [self closeProcessListWindow];
                }
                
                // Show preferences window
                [self.preferencesController openPreferencesWindow];
                
            } else {
                // Show preferences window
                DDLogDebug(@"openPreferences: Preferences already open, just show Window");
                // Release preferences window so buttons get enabled properly for the local client settings mode
                [self.preferencesController releasePreferencesWindow];
                // Re-initialize and open preferences window
                [self.preferencesController initPreferencesWindow];
                [self.preferencesController reopenPreferencesWindow];
                [self.preferencesController showPreferencesWindow:nil];
            }
        }
    }
}


- (void)closePreferencesWindow
{
    // Release preferences window so buttons get enabled properly for the local client settings mode
    [self.preferencesController releasePreferencesWindow];
    [self.preferencesController initPreferencesWindow];
}


- (void)preferencesClosed:(NSNotification *)notification
{
    DDLogInfo(@"Preferences window closed, no reconfiguration necessary");
    [configMenu setHidden:YES];

    [self updateAACAvailablility];
    if (_startingUp) {
        [self preferencesOpenedWhileStartingUpNowClosing];
    } else {
        [self performAfterPreferencesClosedActions];
        
        // Update URL filter flags and rules
        [[SEBURLFilter sharedSEBURLFilter] updateFilterRulesWithStartURL:self.startURL];
        // Update URL filter ignore rules
        [[SEBURLFilter sharedSEBURLFilter] updateIgnoreRuleList];
        
        // Reinforce kiosk mode after a delay, so eventually visible fullscreen apps get hidden again
        [self performSelector:@selector(reinforceKioskMode) withObject: nil afterDelay: 1];
    }
}


- (void)preferencesClosedRestartSEB:(NSNotification *)notification
{
    [configMenu setHidden:YES];
    
    [self updateAACAvailablility];
    if (_startingUp) {
        [self preferencesOpenedWhileStartingUpNowClosing];
    } else {
        DDLogInfo(@"Preferences window closed, reconfiguring to new settings");

        [self performAfterPreferencesClosedActions];
        
        [self sessionQuitRestart:YES];

        // Reinforce kiosk mode after a delay, so eventually visible fullscreen apps get hidden again
        [self performSelector:@selector(reinforceKioskMode) withObject: nil afterDelay: 1];
    }
}


- (void)preferencesOpenedWhileStartingUpNowClosing
{
    if (!quittingMyself) {
        DDLogInfo(@"Preferences window was opened while starting up SEB, continue now to start up.");
        // We need to reset this flag, as settings to be opened are already active
        _openingSettings = NO;
        [self didFinishLaunchingWithSettings];
    } else {
        DDLogInfo(@"Preferences window was opened while starting up SEB, and quit was selected while the Preferences window was still open.");
    }
}


- (void)performAfterPreferencesClosedActions
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    
    [preferences setSecureBool:NO forKey:@"org_safeexambrowser_elevateWindowLevels"];
    
    if (_isAACEnabled == NO) {
        // Open new covering background windows on all currently available screens
        DDLogInfo(@"Preferences window closed, reopening cap windows.");
        [self coverScreens];
    }
    
    // Change window level of all open browser windows to normal levels
    // this helps to get rid of full screen apps on separate spaces (on other displays)
    [self.browserController browserWindowsChangeLevelAllowApps:YES];
    
    if (_isAACEnabled == NO) {
        // Switch the kiosk mode on again
        [self setElevateWindowLevels];
        
        BOOL allowSwitchToThirdPartyApps = ![preferences secureBoolForKey:@"org_safeexambrowser_elevateWindowLevels"];
        [self switchKioskModeAppsAllowed:allowSwitchToThirdPartyApps overrideShowMenuBar:NO];
    }
}


- (void) requestedShowAbout:(NSNotification *)notification
{
    [self showAbout:self];
}

- (IBAction)showAbout:(id)sender
{
    if (_alternateKeyPressed == NO) {
        [self.aboutWindow setStyleMask:NSWindowStyleMaskBorderless];
        [self.aboutWindow center];
        //[self.aboutWindow orderFront:self];
        //[self.aboutWindow setLevel:NSMainMenuWindowLevel];
        [NSApp runModalForWindow:self.aboutWindow];
    }
}


- (void) requestedShowHelp:(NSNotification *)notification
{
    [self showHelp:self];
}


// Load manual page URL in new browser window
- (IBAction) showHelp: (id)sender
{
    NSString *urlString = SEBHelpPage;
    // Open new browser window containing WebView and show it
    [self.browserController openAndShowWebViewWithURL:[NSURL URLWithString:urlString] configuration:nil];
}


- (void) closeDocument:(id)document
{
    [document close];
}


- (IBAction)shareConfigFormatSelected:(id)sender
{
    [[NSUserDefaults standardUserDefaults] setSecureInteger:_shareConfigFormatPopUpButton.indexOfSelectedItem forKey:@"org_safeexambrowser_shareConfigFormat"];
    _shareConfigUncompressedButton.hidden = !_preferencesController.canSavePlainText;
}

- (IBAction)shareConfigUncompressedSelected:(id)sender
{
    [[NSUserDefaults standardUserDefaults] setSecureBool:_shareConfigUncompressedButton.state forKey:@"org_safeexambrowser_shareConfigUncompressed"];
}


#pragma mark - Quitting/Restarting Sessions and SEB

// [P2R1 F5] Forward declarations for the ONE exit-code normalisation and its two consumers. The
// definitions live together under the BEGIN/END blinkeredExitCodeNormalisation markers further down
// (the deploy gate slices that region out and drives it over the golden vectors); they are declared
// here because the quit dialog — the first consumer — appears above them in this file.
static NSString *BlinkeredNormaliseExitCode(NSString *code);
static BOOL BlinkeredExitCodeMatchesBakedHash(NSString *typed, NSString *bakedHash);
static NSString *BlinkeredExitProofDigest(NSString *code, NSString *sessionId);

- (IBAction) requestedQuit:(id)sender
{
    BOOL quittingFromSPSCacheUpload = NO;
    id senderObject;
    if ([sender respondsToSelector:@selector(object)]) {
        senderObject = [sender object];
        Class senderClass = [senderObject class];
        DDLogDebug(@"%s sender.object: %@, object.class: %@", __FUNCTION__, senderObject, senderClass);
        quittingFromSPSCacheUpload = [senderClass isEqualTo:TransmittingCachedScreenShotsViewController.class];
    }
    if (!quittingFromSPSCacheUpload && _screenProctoringController && _screenProctoringController.sessionIsClosing) {
        return;
    }
    // Blinkered: in a home session, route Quit (menu / Cmd+Q) to the in-page styled exit-code
    // modal — validated on the server against the signed-in child's code, so it works on shared
    // devices — instead of SEB's native quit-password dialog (whose .seb password is random on a
    // shared device). The modal navigates to the quit URL on success, which quits normally.
    if (!quittingFromSPSCacheUpload && [self blinkeredShowHomeExitModal]) {
        return;
    }
    // Load quitting preferences from the system's user defaults database
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    // Check for a per-class quit hash. Written by the /seb-setsession interceptor on class
    // join. (The /seb-setquit interceptor that also wrote it was removed — see
    // SEBAbstractWebView.m and SEB_QUIT_HARDENING_PLAN §1.6.)
    NSString *hashedQuitPassword = nil;
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *hashFilePath = [[appSupport stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"class_quit_hash.txt"];
    NSString *fileHash = [NSString stringWithContentsOfFile:hashFilePath encoding:NSUTF8StringEncoding error:nil];
    BOOL hasClassSession = [fileHash isKindOfClass:[NSString class]] && fileHash.length == 64;
    if (hasClassSession) {
        hashedQuitPassword = fileHash;
    } else {
        hashedQuitPassword = [preferences secureObjectForKey:@"org_safeexambrowser_SEB_hashedQuitPassword"];
    }
    // Allow quit if the pref says so, OR if there's no active class session (student hasn't joined a class yet).
    BOOL noActiveClass = !hasClassSession && (hashedQuitPassword.length == 0 || [hashedQuitPassword isEqualToString:@""]);
    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowQuit"] == YES || noActiveClass) {
        NSWindow *currentMainWindow = self.browserController.mainBrowserWindow;
        if (self.settingsOpen ) {
            currentMainWindow = self.preferencesController.preferencesWindow;
            DDLogDebug(@"Preferences are open, displaying according alerts as sheet on window %@", currentMainWindow);
        }
        // if quitting SEB is allowed
        [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];

        if (quittingFromSPSCacheUpload) {
            currentMainWindow = nil;
        }
        
        if (![hashedQuitPassword isEqualToString:@""]) {
            // §2.6: throttle the HOME-session quit dialog (5 wrong → 60 s, doubling, cap 15 min).
            // Class/exam sessions keep stock behaviour. Checked before the dialog so the lockout
            // also stops the dialog being a feedback oracle.
            BOOL isHomeQuit = !hasClassSession && [self blinkeredHomeSessionInfo] != nil;
            if (isHomeQuit && !quittingFromSPSCacheUpload) {
                NSTimeInterval lockoutRemaining = [self blinkeredQuitDialogLockoutRemaining];
                if (lockoutRemaining > 0) {
                    DDLogWarn(@"Blinkered: home quit dialog locked out (%.0f s remaining)", lockoutRemaining);
                    NSAlert *lockoutAlert = [self newAlert];
                    [lockoutAlert setMessageText:@"Too many wrong codes"];
                    [lockoutAlert setInformativeText:[NSString stringWithFormat:@"Try again in %ld second%@.",
                                                      (long)ceil(lockoutRemaining), ceil(lockoutRemaining) == 1 ? @"" : @"s"]];
                    [lockoutAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                    [lockoutAlert setAlertStyle:NSAlertStyleWarning];
                    void (^lockoutOK)(NSModalResponse) = ^void (NSModalResponse answer) {
                        [self removeAlertWindow:lockoutAlert.window];
                    };
                    [self runModalAlert:lockoutAlert conditionallyForWindow:currentMainWindow completionHandler:lockoutOK];
                    return;
                }
            }
            DDLogInfo(@"%s Displaying quit password alert", __FUNCTION__);
            // if quit password is set, then restrict quitting
            if ([self showEnterPasswordDialog:NSLocalizedString(@"Enter quit password:", @"") modalForWindow:currentMainWindow pseudoModal:quittingFromSPSCacheUpload windowTitle:@""] == SEBEnterPasswordCancel) return;
            NSString *password = [self.enterPassword stringValue];

            SEBKeychainManager *keychainManager = [[SEBKeychainManager alloc] init];
            // Home-quit entry hygiene: the Master Exit Code is displayed grouped (XXXX-XXXX-XXXX,
            // uppercase) and typed rarely, so ALSO accept a normalised form — separators/whitespace
            // stripped + uppercased. The raw entry is still tried first, so no password that worked
            // before stops working (a class/exam quit password may legitimately contain a hyphen).
            BOOL passwordMatches = hashedQuitPassword &&
                [hashedQuitPassword caseInsensitiveCompare:[keychainManager generateSHAHashString:password]] == NSOrderedSame;
            // [P2R1 F5] The normalised attempt goes through the ONE normalisation — the same string
            // the proof digest is keyed on. This used to strip a narrower set (`-`, en dash, em dash
            // and whitespace only), so a code pasted with U+2011 from a password manager was refused
            // HERE while the proof path would have accepted it: two definitions of "the same code",
            // one screen apart, and the golden vectors only covered the other one.
            if (!passwordMatches && isHomeQuit && hashedQuitPassword) {
                passwordMatches = BlinkeredExitCodeMatchesBakedHash(password, hashedQuitPassword);
            }
            if (passwordMatches) {
                // if the correct quit password was entered
                DDLogInfo(@"Correct quit password entered");
                if (isHomeQuit) {
                    [self blinkeredQuitThrottleReset];
                    _blinkeredQuitMethod = @"master_code";   // §2.5: how this quit passed, for the parent-exit marker
                    _blinkeredQuitTypedCode = password;      // [R6] proof material — cleared once the marker is written
                }
                if (!quittingFromSPSCacheUpload) {
                    // Notify server before quitting so teacher sees student leave instantly.
                    [self notifyServerQuitWithCompletion:^{ [self quitSEBOrSession]; }];
                } else {
                    // Quit from uploading cached screen shots: Don't confirm quitting
                    [self quitFromTransmittingCachedScreenShots];
                }

            } else {
                // Wrong quit password was entered
                DDLogInfo(@"Wrong quit password entered");
                if (isHomeQuit) [self blinkeredQuitThrottleRecordFailure];
                if (!quittingFromSPSCacheUpload) {
                    NSAlert *modalAlert = [self newAlert];
                    [modalAlert setMessageText:NSLocalizedString(@"Wrong Quit Password", @"")];
                    [modalAlert setInformativeText:NSLocalizedString(@"If you don't enter the correct quit password, then you cannot quit.", @"")];
                    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                    [modalAlert setAlertStyle:NSAlertStyleWarning];
                    void (^wrongPasswordEnteredOK)(NSModalResponse) = ^void (NSModalResponse answer) {
                        [self removeAlertWindow:modalAlert.window];
                    };
                    [self runModalAlert:modalAlert conditionallyForWindow:currentMainWindow completionHandler:(void (^)(NSModalResponse answer))wrongPasswordEnteredOK];
                }
            }
        } else {
            // If no quit password is required, then confirm quitting, with default option "Quit"
            DDLogInfo(@"%s No quit password required, continue", __FUNCTION__);
            if (!quittingFromSPSCacheUpload) {
                // Use the server-notification variant so teacher is notified on confirm.
                [self blinkeredSessionQuitWithServerNotification:NO];
            } else {
                // Quit from uploading cached screen shots: Don't confirm quitting
                [self quitFromTransmittingCachedScreenShots];
            }
        }
    }
}

// Notify the Blinkered server that the student is quitting via the native mechanism,
// then call completion (on the main thread) to proceed with the actual quit.
// Reads class_session.json written by the /seb-setsession URL interceptor.
// Best-effort: if the server is unreachable the 3-second timeout still calls completion.
- (void)notifyServerQuitWithCompletion:(void (^)(void))completion
{
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir = [appSupport stringByAppendingPathComponent:@"Blinkered"];

    // ── [P2R1 F11] Take the quit credentials ONCE, here, and clear them immediately ───────────────
    // These three statics describe THIS quit and must not survive it down any path. They used to be
    // read and cleared inside the home branch alone, so a quit that took the class branch (or the
    // no-session-file branch) left a typed Master Exit Code sitting in process memory until the next
    // home quit consumed it — including the case where the NEXT quit was a free one and would then
    // have carried the earlier code's proof. Capturing at the top makes "cleared on every non-home
    // path" structural rather than something four branches each have to remember.
    NSString *quitMethod     = _blinkeredQuitMethod;      // NO default — see below
    NSString *quitTypedCode  = _blinkeredQuitTypedCode;
    NSString *quitSessionIdOverride = _blinkeredQuitSessionId;
    _blinkeredQuitMethod    = nil;
    _blinkeredQuitTypedCode = nil;   // [R6] never outlive this quit
    _blinkeredQuitSessionId = nil;

    // ── Home session (check first) ────────────────────────────────────────────
    NSString *homeSessionPath = [dir stringByAppendingPathComponent:@"home_session.json"];
    NSData *homeData = [NSData dataWithContentsOfFile:homeSessionPath];
    if (homeData) {
        NSDictionary *homeInfo = [NSJSONSerialization JSONObjectWithData:homeData options:0 error:nil];
        NSString *deviceId = homeInfo[@"id"];
        NSString *token    = homeInfo[@"token"];
        NSString *base     = homeInfo[@"base"];
        if (deviceId.length > 0 && token.length > 0 && base.length > 0) {
            [[NSFileManager defaultManager] removeItemAtPath:homeSessionPath error:nil];
            // §2.5 [R1-2]: the sessionId this quit legitimately ended — captured before the file is
            // gone, needed if the notification can't be delivered (offline/intercepting network).
            //
            // [P2R2-2] A BRIDGE exit overrides it with the sid the PAGE was served with. The proof is
            // verified server-side against `device.sessionId`, and home_session.json is written ONCE
            // at lock-page launch — but the F0b permissive-bake re-lock mints a FRESH session_id on an
            // already-locked device WITHOUT re-baking, so the code still matches locally while the
            // stale sid makes the proof unverifiable. The page's initData.sessionId is re-stamped on
            // every page load, which that re-lock forces, so it is the freshest source of the sid the
            // server actually holds. It fails CLOSED: a stale or forged sid yields a proof the server
            // refuses, the device re-locks, and nothing opens.
            NSString *fileSessionId = [homeInfo[@"sessionId"] isKindOfClass:[NSString class]] ? homeInfo[@"sessionId"] : nil;
            NSString *quitSessionId = quitSessionIdOverride.length > 0 ? quitSessionIdOverride : fileSessionId;
            if (quitSessionIdOverride.length > 0 && ![quitSessionIdOverride isEqualToString:fileSessionId ?: @""]) {
                DDLogInfo(@"Blinkered: bridge exit — proving against the PAGE's sessionId, which differs from home_session.json's (F0b re-lock shape)");
            }
            NSString *urlStr = [NSString stringWithFormat:@"%@/api/home/devices/%@/native-quit", base, deviceId];
            NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]
                                                                   cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                               timeoutInterval:3.0];
            request.HTTPMethod = @"POST";
            // §14.2 item 4 / F5: the proof rides the ONLINE notify too, not just the offline marker.
            // Its server half went live with seb-classroom #595: a `/native-quit` carrying a valid
            // master proof runs the full master-exit pipeline (stand-down, latch, truthful
            // `master_code_exit` alert, burn-on-use rotation) instead of unlocking and then
            // re-deriving the schedule — and, under block-all, is HONOURED rather than 403'd. Without
            // this, a parent standing at a device with a signal typed their own code and watched the
            // app relaunch in their face. Absent proof → byte-for-byte the old body, so a free quit
            // and a class quit are unchanged.
            NSString *onlineProof = BlinkeredExitProofDigest(quitTypedCode, quitSessionId);
            NSMutableDictionary *bodyDict = [@{ @"token": token } mutableCopy];
            if (onlineProof.length) bodyDict[@"proof"] = onlineProof;
            request.HTTPBody = [NSJSONSerialization dataWithJSONObject:bodyDict options:0 error:nil];
            [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            DDLogInfo(@"Blinkered: notifying server of home session quit (device %@, proof %@)",
                      deviceId, onlineProof.length ? @"attached" : @"none");
            NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
            config.timeoutIntervalForRequest  = 3.0;
            config.timeoutIntervalForResource = 3.0;
            [[[NSURLSession sessionWithConfiguration:config]
              dataTaskWithRequest:request
              completionHandler:^(NSData *d, NSURLResponse *resp, NSError *err) {
                NSInteger status = [resp isKindOfClass:[NSHTTPURLResponse class]] ? ((NSHTTPURLResponse *)resp).statusCode : 0;
                BOOL delivered = (err == nil && status >= 200 && status < 300);
                if (delivered) {
                    DDLogInfo(@"Blinkered: home session server notified (status %ld)", (long)status);
                } else {
                    DDLogWarn(@"Blinkered: home quit notification failed (%@) — writing parent-exit marker",
                              err ? err.localizedDescription : [NSString stringWithFormat:@"status %ld", (long)status]);
                    // §2.5 [R1-2]: the server never heard this legitimate exit — without a marker the
                    // agent re-locks from cache in ~20 s (a 20-second placebo). The marker is consumed
                    // per-sessionId by all three agent relaunch paths and reported/reconciled on the
                    // agent's next successful poll. No marker without a sessionId (old session file):
                    // the agent then re-locks — the accepted old-app residual, never a fail-open.
                    if (quitSessionId.length > 0) {
                        // [R6] Bind the proof to THIS sessionId so a digest that is somehow observed
                        // once cannot be replayed against a different lock. Only the digest is written
                        // to disk — the marker file is kid-readable, and it must teach nothing about
                        // the code itself.
                        NSString *proof = onlineProof;
                        NSMutableDictionary *marker = [@{ @"sessionId": quitSessionId,
                                                          @"exitedAt": @((long long)([NSDate date].timeIntervalSince1970 * 1000)) } mutableCopy];
                        // [P2R1 F11] NO `?: @"master_code"` default. The old code defaulted an ABSENT
                        // method to "master_code", so a quit that never passed the code gate — a free
                        // quit, a path that simply forgot to set it — wrote a marker claiming the
                        // parent had typed their code. An absent method stays absent, and the server
                        // reads the claim for what it is.
                        if (quitMethod.length) marker[@"method"] = quitMethod;
                        if (proof.length) marker[@"proof"] = proof;
                        NSData *markerData = [NSJSONSerialization dataWithJSONObject:marker options:0 error:nil];
                        if (markerData) [markerData writeToFile:[dir stringByAppendingPathComponent:@"parent-exit.json"] atomically:YES];
                    } else {
                        DDLogWarn(@"Blinkered: no sessionId in home_session.json — cannot write parent-exit marker (agent may re-lock)");
                    }
                }
                dispatch_async(dispatch_get_main_queue(), ^{ completion(); });
            }] resume];
            return;
        }
    }

    // ── Class session ─────────────────────────────────────────────────────────
    NSString *sessionPath = [dir stringByAppendingPathComponent:@"class_session.json"];
    NSData *fileData = [NSData dataWithContentsOfFile:sessionPath];
    if (!fileData) {
        DDLogInfo(@"Blinkered: no session file — skipping server quit notification");
        completion();
        return;
    }
    NSDictionary *sessionInfo = [NSJSONSerialization JSONObjectWithData:fileData options:0 error:nil];
    NSString *code  = sessionInfo[@"code"];
    NSString *token = sessionInfo[@"token"];
    NSString *base  = sessionInfo[@"base"];
    if (!(code.length > 0 && token.length > 0 && base.length > 0)) {
        DDLogWarn(@"Blinkered: class_session.json is malformed — skipping notification");
        completion();
        return;
    }
    // Delete immediately to prevent a double-notification if called again before quit.
    [[NSFileManager defaultManager] removeItemAtPath:sessionPath error:nil];

    NSString *urlStr = [NSString stringWithFormat:@"%@/api/class/%@/native-quit", base, code];
    NSURL *endpointURL = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:endpointURL
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                       timeoutInterval:3.0];
    request.HTTPMethod = @"POST";
    NSString *bodyStr = [NSString stringWithFormat:@"{\"token\":\"%@\"}", token];
    request.HTTPBody = [bodyStr dataUsingEncoding:NSUTF8StringEncoding];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    DDLogInfo(@"Blinkered: notifying server of native quit (class %@)", code);
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.timeoutIntervalForRequest  = 3.0;
    config.timeoutIntervalForResource = 3.0;
    NSURLSession *urlSession = [NSURLSession sessionWithConfiguration:config];
    [[urlSession dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            DDLogWarn(@"Blinkered: server quit notification failed: %@", error.localizedDescription);
        } else {
            DDLogInfo(@"Blinkered: server notified of native quit (status %ld)",
                      (long)((NSHTTPURLResponse *)response).statusCode);
        }
        dispatch_async(dispatch_get_main_queue(), ^{ completion(); });
    }] resume];
}

// Variant of sessionQuitRestartIgnoringQuitPW: that notifies the server before proceeding.
// Used only from requestedQuit: (student-initiated quit, no password).
- (void)blinkeredSessionQuitWithServerNotification:(BOOL)restart
{
    DDLogDebug(@"%s Displaying confirm quit alert (with server notification)", __FUNCTION__);
    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    NSAlert *modalAlert = [self newAlert];
    [modalAlert setMessageText:restart
        ? NSLocalizedString(@"Restart Session", @"")
        : (!self.quittingSession
            ? [NSString stringWithFormat:NSLocalizedString(@"Quit %@", @""), SEBFullAppNameClassic]
            : NSLocalizedString(@"Quit Session", @""))];
    [modalAlert setInformativeText:restart
        ? NSLocalizedString(@"Are you sure you want to restart this session?", @"")
        : (!self.quittingSession
            ? [NSString stringWithFormat:NSLocalizedString(@"Are you sure you want to quit %@?", @""), SEBFullAppNameClassic]
            : NSLocalizedString(@"Are you sure you want to quit this session?", @""))];
    [modalAlert addButtonWithTitle:restart ? NSLocalizedString(@"Restart", @"") : NSLocalizedString(@"Quit", @"")];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
    [modalAlert setAlertStyle:NSAlertStyleWarning];
    void (^quitSEBAnswer)(NSModalResponse) = ^void (NSModalResponse answer) {
        [self removeAlertWindow:modalAlert.window];
        switch (answer) {
            case NSAlertFirstButtonReturn:
                if (self.settingsOpen) {
                    DDLogInfo(@"Confirmed to quit, preferences window is open");
                    [self.preferencesController quitSEB:self];
                } else {
                    DDLogInfo(@"Confirmed to %@ %@", restart ? @"restart" : @"quit",
                              !self.quittingSession ? SEBShortAppName : @"exam session");
                    // §2.5: a confirmed free quit of a self-exit home session — record how this quit
                    // passed so a failed server notification writes the right parent-exit marker.
                    if ([self blinkeredHomeSessionInfo]) _blinkeredQuitMethod = @"self_exit";
                    [self notifyServerQuitWithCompletion:^{
                        [self sessionQuitRestart:restart];
                    }];
                }
                return;
            default:
                DDLogDebug(@"%s canceled quit alert (NSModalResponse %ld).", __FUNCTION__, (long)answer);
                return;
        }
    };
    [self runModalAlert:modalAlert
    conditionallyForWindow:self.browserController.mainBrowserWindow
         completionHandler:(void (^)(NSModalResponse answer))quitSEBAnswer];
}

// Quit from uploading cached screen shots and don't confirm quitting SEB/Session
- (void) quitFromTransmittingCachedScreenShots
{
    [self closeTransmittingCachedScreenShotsWindow:^{
        [self.screenProctoringController continueClosingSessionWithCompletionHandler:^{
            self->_screenProctoringController = nil;
            [self sessionQuitRestart:NO];
        }];
    }];
}


- (void) quitLinkDetected:(NSNotification *)notification
{
    // Check-only dedupe (M1). The page posts a native `quit` AND, 2 s later, navigates to /seb-quit as
    // the old-build fallback — on a new build both arrive here. Re-entering exitSEB would restart the
    // cookie save while the first one is still in flight. CHECK only, and only at the page entry
    // points: exitSEB itself must never early-return, or the designed AAC double-entry breaks.
    if (BlinkeredTeardownStarted()) {
        DDLogInfo(@"Quit Link invoked — teardown already running, ignoring");
        return;
    }
    DDLogInfo(@"Quit Link invoked — exiting");
    [self exitSEB];
}


// Confirm quitting, with default option "Quit"
- (void)sessionQuitRestartIgnoringQuitPW:(BOOL)restart
{
    DDLogDebug(@"%s Displaying confirm quit alert", __FUNCTION__);
    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    NSAlert *modalAlert = [self newAlert];
    [modalAlert setMessageText:restart ? NSLocalizedString(@"Restart Session", @"") : (!self.quittingSession ? [NSString stringWithFormat:NSLocalizedString(@"Quit %@", @""), SEBFullAppNameClassic] : NSLocalizedString(@"Quit Session", @""))];
    [modalAlert setInformativeText:restart ? NSLocalizedString(@"Are you sure you want to restart this session?", @"") : (!self.quittingSession ? [NSString stringWithFormat:NSLocalizedString(@"Are you sure you want to quit %@?", @""), SEBFullAppNameClassic] : NSLocalizedString(@"Are you sure you want to quit this session?", @""))];
    [modalAlert addButtonWithTitle:restart ? NSLocalizedString(@"Restart", @"") : NSLocalizedString(@"Quit", @"")];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
    [modalAlert setAlertStyle:NSAlertStyleWarning];
    void (^quitSEBAnswer)(NSModalResponse) = ^void (NSModalResponse answer) {
        [self removeAlertWindow:modalAlert.window];
        switch(answer)
        {
            case NSAlertFirstButtonReturn:
                if (self.settingsOpen) {
                    DDLogInfo(@"Confirmed to quit, preferences window is open");
                    [self.preferencesController quitSEB:self];
                } else {
                    DDLogInfo(@"Confirmed to %@ %@", restart ? @"restart" : @"quit", !self.quittingSession ? SEBShortAppName : @"exam session");
                    [self sessionQuitRestart:restart];
                }
                return;
            default:
            {
                DDLogDebug(@"%s canceled quit alert with NSModalResponse %ld.", __FUNCTION__, (long)answer);
                return; //Cancel: don't quit
            }
        }
    };
    [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))quitSEBAnswer];
}


// Quit or restart session without asking for confirmation

- (void) sessionQuitRestart:(BOOL)restart
{
    DDLogDebug(@"%s restart: %d", __FUNCTION__, restart);
    _openingSettings = NO;

    // In case of AAC Multi App Mode, we have to terminate running permitted applications
    [self terminateApplications:@[] processes:@[] starting:NO restarting:restart callback:nil selector:nil];
}

- (void) sessionQuitRestartContinue:(BOOL)restart
{
    DDLogDebug(@"%s restart: %d", __FUNCTION__, restart);

    NSArray *permittedProcesses = [ProcessManager sharedProcessManager].permittedProcesses;
    if (permittedProcesses.count > 0) {
        BOOL removedSavedWindowState = [self.assessmentConfigurationManager removeSavedAppWindowStateWithPermittedApplications:permittedProcesses];
        DDLogInfo(@"Removing saved window state for permitted applications before quitting SEB was %@successful.", removedSavedWindowState ? @"" : @"not ");
    }

    [AccessibilityFeaturesManager restoreVoiceOver];

    // Stop/Reset proctoring
    [self stopProctoringWithCompletion:^{
        DDLogDebug(@"%s Conditionally closed (optional) proctoring", __FUNCTION__);
        [self conditionallyCloseSEBServerConnectionWithRestart:restart completion:^(BOOL restart) {
            self.establishingSEBServerConnection = NO;
            DDLogDebug(@"%s Conditionally closed (optional) SEB Server connection (restart: %d)", __FUNCTION__, restart);
            run_on_ui_thread(^{
                [self didCloseSEBServerConnectionRestart:restart];
            });
        }];
    }];
}


- (void) quitSEBOrSession
{
    DDLogDebug(@"[SEBController quitSEBOrSession]");
    if (self.quittingSession) {
        [NSUserDefaults setUserDefaultsPrivate:NO];
        [self updateAACAvailablility];
        [self requestedRestart];
    } else {
        [self requestedExit:nil];
    }
}

#pragma mark - Blinkered offline exit (OFFLINE_EXIT_CODE_PLAN.md)

// Single-instance controller state for the offline-exit flows (file statics avoid a header change).
static BOOL _blinkeredSkipHomeExitModal = NO;      // async fallback re-entry: go straight to the native dialog
static BOOL _blinkeredOfflinePanelShowing = NO;
// [3.6.201] Condition (c) of OFFLINE_RETRY_FIX2_V2_REVIEW's dismissal ruling: the retry can only
// dismiss the panel if it can NAME it. Identity, not "some modal is up" — that distinction is what
// stopped the original proposal from ending the parent's own exit dialog by mistake.
static NSAlert *_blinkeredOfflinePanelAlert = nil;
static NSDate *_blinkeredOfflinePanelLastShown = nil;
// R2-F3. "Is a RAISE PENDING", which is what the enqueue guard actually needs — not "is a panel
// showing", which is what it used to ask. The two differ for exactly the window the guard was
// written for: the panel's completion handler clears _blinkeredOfflinePanelShowing BEFORE
// -requestedQuit: opens its inline nested exit-code modal, so while a parent stands at that dialog
// the flag reads NO and every failure enqueues again behind a main queue that cannot drain.
static BOOL _blinkeredOfflinePanelRaisePending = NO;
// R2-F2. Raised once per OUTAGE, not once per failed retry. See -blinkeredHomeConnectivityFailed:.
static BOOL _blinkeredOfflinePanelRaisedThisOutage = NO;
// [P2R1 F14] When the page last swallowed a Cmd+Q. Bounded: 10 s, consumed on use, cleared on a page
// navigation (chromeReady). See blinkeredShowHomeExitModal.
static NSDate *_blinkeredLastSwallowedQuit = nil;
// ── [P2R1 F5] ONE normalisation, and everything that consumes it ─────────────────────────────────
//
// Two normalisations lived in this file. The PROOF key stripped every Unicode dash + a BOM; the quit
// dialog's own comparison (requestedQuit:) stripped only `-`, en dash, em dash and whitespace. So a
// parent pasting a code containing U+2011 from a password manager was told the code was WRONG at the
// dialog — and on any input the looser set let through, the proof that followed was computed from a
// different string than the compare had accepted. Two definitions of "the same code" is the exact
// defect the golden vectors exist to make impossible, reintroduced one screen away from them.
//
// So: ONE normaliser, with the compare and the digest both derived from it. The region between the
// markers is COMPILED BY THE DEPLOY GATE — tools/lockdown-tests/run-master-code-bridge-test.sh slices
// it out of this file and drives it over the same golden vectors seb-classroom asserts against, now
// covering the COMPARE (SHA-256 of the normalised code — which is what the baked hashedQuitPassword
// is) and not only the digest. Do not move or rename the markers.
//
// BEGIN blinkeredExitCodeNormalisation
static NSString *BlinkeredNormaliseExitCode(NSString *code)
{
    if (code.length == 0) return @"";
    // [R8 A] Strip EVERY Unicode dash (U+2010-U+2015), not just en/em. The ship review built the
    // differential test this code never had and found five inputs where the app and the server
    // disagreed — U+2010 HYPHEN, U+2011 NON-BREAKING HYPHEN, U+2012 FIGURE DASH, U+2015 HORIZONTAL
    // BAR, and a U+FEFF BOM prefix. A password manager renders a code with U+2011 precisely so it
    // does not wrap, so a parent pasting from one produced a digest the server could never
    // reproduce: their genuine exit refused, the device re-locked, and an invisible character as
    // the only cause. This set must stay identical to seb-classroom's offlineExitProof.js — the
    // golden vectors in tools/lockdown-tests/ enforce it on every release.
    NSMutableCharacterSet *strip = [NSMutableCharacterSet characterSetWithRange:NSMakeRange(0x2010, 6)];
    // [R2-4 upstream, 16 Aug] The invisible-paste class + the dash-likes the U+2010 range missed.
    // Field evidence (W-A review R2-4): a code pasted with one of these was REFUSED here while
    // Windows' keep-list accepted it — fail-closed at the break-glass door with an invisible cause.
    // Dash-likes: U+2212 MINUS, U+FF0D FULLWIDTH HYPHEN, U+FE63 SMALL HYPHEN-MINUS. Invisibles:
    // U+00AD SOFT HYPHEN, U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+200E LRM, U+200F RLM, U+2060
    // WORD JOINER. Deletion-only, never translation — none is in the code alphabet, so stripping
    // can never merge two distinct codes. Escaped, as ever: invisible literals are unreviewable.
    [strip addCharactersInString:@"-\uFEFF\u2212\uFF0D\uFE63\u00AD\u200B\u200C\u200D\u200E\u200F\u2060\u061C\u180E\u202A\u202B\u202C\u202D\u202E\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069"];
    [strip formUnionWithCharacterSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return [[[code componentsSeparatedByCharactersInSet:strip] componentsJoinedByString:@""] uppercaseString];
}

// Lowercase-hex SHA-256 — the shape the server bakes into the .seb as hashedQuitPassword
// (seb-classroom's hashPassword()). Duplicating SEBKeychainManager's generateSHAHashString: here is
// deliberate and safe: SHA-256 has no dialect to drift into, and the sliced region must compile in
// the contract test without dragging the keychain manager (and half the app) in with it.
static NSString *BlinkeredSHA256Hex(NSString *s)
{
    NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    unsigned char out[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(d.bytes, (CC_LONG)d.length, out);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", out[i]];
    return hex;
}

// THE COMPARE. `bakedHash` is the hashedQuitPassword the server baked into this session's .seb — on
// a home lock that is SHA-256 of the parent's Master Exit Code as stored. Fails closed on every
// degenerate input: no code, no hash, a hash that is not a 64-hex digest, or a code that normalises
// away to nothing (a field holding only hyphens must never match anything).
static BOOL BlinkeredExitCodeMatchesBakedHash(NSString *typed, NSString *bakedHash)
{
    if (typed.length == 0 || bakedHash.length != 64) return NO;
    NSString *normalised = BlinkeredNormaliseExitCode(typed);
    if (normalised.length == 0) return NO;
    return [bakedHash caseInsensitiveCompare:BlinkeredSHA256Hex(normalised)] == NSOrderedSame;
}

// [R6] HMAC-SHA256(key: the normalised typed code, message: sessionId), lowercase hex. The key is the
// SAME normalised string the compare above accepted — that identity is the point of this region.
static NSString *BlinkeredExitProofDigest(NSString *code, NSString *sessionId)
{
    if (code.length == 0 || sessionId.length == 0) return nil;
    NSString *key = BlinkeredNormaliseExitCode(code);
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *msgData = [sessionId dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keyData.bytes, keyData.length, msgData.bytes, msgData.length, mac);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", mac[i]];
    return hex;
}
// END blinkeredExitCodeNormalisation

- (NSString *)blinkeredExitProofForCode:(NSString *)code session:(NSString *)sessionId
{
    return BlinkeredExitProofDigest(code, sessionId);
}

static NSString *_blinkeredQuitMethod = nil;       // "master_code" | "self_exit" — how the current native quit passed
// [R6] The code the parent actually TYPED at the quit dialog, held only long enough to derive the
// offline-exit proof below, then cleared. `method` alone was an unverifiable assertion: anyone holding
// the device token (readable from the locked page) could POST "the parent exited me offline with the
// master code" and the server obeyed. The proof turns the claim into evidence.
static NSString *_blinkeredQuitTypedCode = nil;
// [P2R2-2] Set ONLY by a bridge exit: the sessionId the PAGE was served with, which the proof binds
// to instead of home_session.json's. See the note at the notify site for why the page is the fresher
// source. nil on every other path, so the native dialog keeps home_session.json exactly as before.
static NSString *_blinkeredQuitSessionId = nil;

// The active home session's identity ({id, token, base, sessionId}) — nil when not in a home lock.
- (NSDictionary *)blinkeredHomeSessionInfo
{
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [[appSupport stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"home_session.json"];
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;
    NSDictionary *info = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [info isKindOfClass:[NSDictionary class]] ? info : nil;
}

// The main browser window's WKWebView, or nil.
- (WKWebView *)blinkeredMainWebView
{
    NSWindow *mainWin = self.browserController.mainBrowserWindow;
    if (!mainWin) return nil;
    id mainAbstract = [mainWin valueForKey:@"webView"];
    if (!mainAbstract || ![mainAbstract respondsToSelector:@selector(nativeWebView)]) return nil;
    id mwk = [mainAbstract performSelector:@selector(nativeWebView)];
    return [mwk isKindOfClass:[WKWebView class]] ? (WKWebView *)mwk : nil;
}

// Issue a recovery navigation to a target already chosen by
// +blinkeredRecoveryTargetForCommittedURL:configuredStartURL:. ONE routing rule for both recovery
// call sites (the offline panel's Retry and the wake-edge wedge reload).
//
// https goes to the raw WKWebView — §3 C3's reviewed status quo. The abstract -reload is gated on
// isReloadAllowed, a policy about whether the KID may refresh; -loadURL: is NOT gated on it, but
// the raw route also skips SEBAbstractModernWebView's per-load content-rule-list recompile, and
// the wake-edge path's budgets and telemetry were reviewed against its timing. Don't perturb it.
//
// Anything else can only be rendered by the app's own load chokepoint (§5 C10). On an
// agent-minted OFFLINE lock the signed config's start URL is `blinkered-offlinecover://<untilMs>`,
// which SEBOSXWKWebViewController.load(_:) intercepts and renders from a compiled-in string;
// a raw loadRequest: of that URL simply fails, so a wedged covered device would have stayed
// wedged. Recovery must go where LAUNCH goes — launch itself uses -loadURL:
// (SEBOSXBrowserController.m:218) — so for those schemes it takes the same route.
//
// Not reachable today (the cover makes no network request, so no offline panel; and it sets no
// __blinkeredLastPaint, so the wake edge reads rAF nosignal and never judges it wedged) — but
// review F6 refused a reachability argument for the twin defect on the committed branch, and the
// same standard applies here.
// R2-F8. Returns whether a navigation was actually ISSUED. The third exit below issues none, and
// callers were stamping ownership, incrementing a counter and logging "NAVIGATING" on the line
// after the call regardless — which is the failure the nil-webview and nil-target bails immediately
// above it were written to avoid, reintroduced one level down.
- (BOOL)blinkeredIssueRecoveryNavigation:(NSURL *)target webView:(WKWebView *)wk
{
    if ([target.scheme.lowercaseString isEqualToString:@"https"]) {
        [self blinkeredNoteRecoveryNavigationIssued];
        [wk loadRequest:[NSURLRequest requestWithURL:target]];
        return YES;
    }
    // NOTE the asymmetry (review R9.2): this lowercases before comparing, but the chokepoint it
    // routes to compares case-sensitively (SEBOSXWKWebViewController.load(_:), `url.scheme ==
    // "blinkered-offlinecover"`). Foundation normalises URL schemes to lower case, so the two
    // agree in practice — but they are two rules at one seam and only one of them says so.
    // A nil scheme is correct by construction: [nil isEqualToString:] is NO, so a scheme-less
    // target takes the chokepoint route, which is the recoverable side.
    NSWindow *mainWin = self.browserController.mainBrowserWindow;
    id mainAbstract = mainWin ? [mainWin valueForKey:@"webView"] : nil;
    if ([mainAbstract respondsToSelector:@selector(loadURL:)]) {
        DDLogInfo(@"Blinkered: recovery target is not https — routing through the load chokepoint so the scheme renders");
        [self blinkeredNoteRecoveryNavigationIssued];
        [mainAbstract performSelector:@selector(loadURL:) withObject:target];
        return YES;
    }
    // Never fall back to the raw route here: it would fail the load and leave the screen as it is,
    // with a log line claiming a navigation happened.
    DDLogError(@"Blinkered: recovery target is not https and the abstract webview is unreachable — no navigation issued");
    return NO;
}

// If the main browser content is a Blinkered home session (/home/…), ask the page to open its
// styled exit-code modal and return YES so the caller skips SEB's native quit dialog. Returns NO
// for non-home sessions (e.g. class sessions) so they're unaffected.
//
// [R1-4] The page's answer arrives ASYNCHRONOUSLY: we schedule the JS with a REAL completion
// handler plus a bounded timer, claim the Quit event now, and fire the native quit path from the
// callback if the page did not confirm it showed a modal (returns literal true — the
// home-content.html contract). evaluateJavaScript's completion is delivered on the MAIN thread and
// requestedQuit: runs on the main thread, so blocking here (a semaphore) would DEADLOCK — the
// decision must re-enter asynchronously. Worst case degrades to "both the page modal and the
// native dialog appear" (cancel one) — never "Cmd+Q does nothing" (the dead-page brick, plan §1b).
- (BOOL)blinkeredShowHomeExitModal {
    if (_blinkeredSkipHomeExitModal) return NO;   // fallback re-entry — take the native path this time
    // ── [P2R1 F14]/[P2R2-14] THE DOUBLE-Cmd+Q HATCH ──────────────────────────────────────────────
    // Cmd+Q must always be reachable. The page contract is "return literal true and I'll suppress the
    // native dialog" — which means an injected `window.blinkeredRequestExit = () => true` sitting over
    // a dead modal can swallow the PRIMARY door indefinitely, and the parent's own way out with it.
    // So a second Cmd+Q within 10 s of one the page swallowed goes straight past the page. P2-R2
    // confirmed nothing else rides this path (today's 0.7 s deadline already re-enters the same
    // requestedQuit:), and the latch is BOUNDED three ways: it expires after 10 s on its own, it is
    // consumed the moment it fires, and a page navigation clears it (the chromeReady bridge message —
    // see SEBBrowserController). It can never stand permanently.
    if (_blinkeredLastSwallowedQuit &&
        [[NSDate date] timeIntervalSinceDate:_blinkeredLastSwallowedQuit] < 10.0) {
        _blinkeredLastSwallowedQuit = nil;                       // consumed — the next Cmd+Q asks the page again
        DDLogWarn(@"Blinkered: second Cmd+Q within 10 s of one the page swallowed — going straight to the native quit dialog");
        return NO;
    }
    _blinkeredLastSwallowedQuit = nil;
    WKWebView *webView = [self blinkeredMainWebView];
    if (!webView) return NO;
    NSString *url = webView.URL.absoluteString ?: @"";
    if ([url rangeOfString:@"/home/"].location == NSNotFound) return NO;   // not a home session
    __block BOOL decided = NO;
    void (^decide)(BOOL, NSString *) = ^(BOOL modalShown, NSString *reason) {
        if (decided) return;
        decided = YES;
        if (modalShown) {
            DDLogInfo(@"Blinkered: home-session Quit — page confirmed the exit modal, native dialog suppressed");
            _blinkeredLastSwallowedQuit = [NSDate date];   // arm the hatch: the NEXT Cmd+Q skips the page
            return;
        }
        DDLogInfo(@"Blinkered: home-session Quit — page did NOT show the exit modal (%@) — falling back to the native quit dialog", reason);
        _blinkeredSkipHomeExitModal = YES;
        [self requestedQuit:nil];
        _blinkeredSkipHomeExitModal = NO;
    };
    [webView evaluateJavaScript:@"window.blinkeredRequestExit && window.blinkeredRequestExit()"
              completionHandler:^(id result, NSError *error) {
        BOOL shown = (error == nil && [result isKindOfClass:[NSNumber class]] && [(NSNumber *)result boolValue]);
        decide(shown, error ? error.localizedDescription : @"no confirmation from page");
    }];
    // Bounded deadline: a wedged page whose completion never arrives must still yield a usable quit.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.7 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        decide(NO, @"timeout");
    });
    return YES;
}

// ── §14.2 THE BRIDGE — the master code validates ON THE DEVICE, in the page's own box ────────────
//
// "The whole idea of a master exit code is that it just gets you out no matter what." (James, 13 Aug.)
//
// Phase 1 put a Master Exit Code field in the lock page's exit modal, but it validates SERVER-side —
// so out of Wi-Fi range, the exact situation the door exists for, the parent's own code did nothing
// but say "no internet, press Cmd+Q instead". This handler makes the SAME box work locally: the code
// is compared against the hash the server baked into this session's .seb, which is the identical
// credential the native Cmd+Q dialog has always accepted offline.
//
// The page reaches this through the origin-gated bridge (SEBBrowserController's allow-list, R1-1),
// which is what makes a page-supplied credential safe to act on at all.
//
// WHAT THIS IS NOT: it is not a new authority. It accepts exactly what Cmd+Q accepts, and on a match
// it runs the native accept path VERBATIM — same method marker, same HMAC proof, same server notify,
// same offline marker. The only thing that changes is which box the parent types into.
//
// [P2R2-17]/[P2R2-18] Every refusal reads as `mismatch` — a wrong code, a class session, an empty or
// absent bake, no session id at all. Indistinguishable from each other, so the reply is never an
// oracle for which state the device is in.
//
// Reply contract ([P2R1 F6]/[P2R2-16]): one of three ENUMERATED LITERALS — no interpolation of
// anything the page sent — delivered to the frame that asked.
- (void)blinkeredMasterCodeBridgeRequest:(NSNotification *)notification
{
    NSDictionary *info = notification.userInfo;
    NSString *code = [info[@"code"] isKindOfClass:[NSString class]] ? info[@"code"] : nil;
    NSString *pageSessionId = [info[@"sessionId"] isKindOfClass:[NSString class]] ? info[@"sessionId"] : nil;
    void (^reply)(NSString *) = info[@"reply"];
    if (!reply) return;

    // ── [P2R1 F8] THE GATE: home lock sessions ONLY ──────────────────────────────────────────────
    // On a CLASS session the baked quit hash is the TEACHER's password. It must never be reachable
    // from a page-driven compare: a student page could then grind the teacher's exam password with no
    // dialog, no throttle and no one watching. Refused outright, and — [P2R2-17] — as `mismatch`, so
    // the refusal teaches nothing about which kind of session is running.
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir = [appSupport stringByAppendingPathComponent:@"Blinkered"];
    NSString *classHash = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:@"class_quit_hash.txt"]
                                                    encoding:NSUTF8StringEncoding error:nil];
    if ([classHash isKindOfClass:[NSString class]] && classHash.length == 64) {
        DDLogWarn(@"Blinkered: master-code bridge REFUSED — a class session is running; the teacher's quit password is not bridge-reachable");
        [self blinkeredMasterCodeBridgeRefuse:reply];
        return;
    }
    NSDictionary *homeInfo = [self blinkeredHomeSessionInfo];
    if (!homeInfo) {
        DDLogWarn(@"Blinkered: master-code bridge REFUSED — no home session (home_session.json absent)");
        [self blinkeredMasterCodeBridgeRefuse:reply];
        return;
    }

    // [P2R1 F8] An EMPTY or ABSENT baked hash REFUSES — it never free-quits. The whole compare rests
    // on this value; treating "nothing to compare against" as "anything matches" would turn a
    // config-write failure into a lock that opens to any string a page cares to post.
    NSString *bakedHash = [[NSUserDefaults standardUserDefaults] secureObjectForKey:@"org_safeexambrowser_SEB_hashedQuitPassword"];
    if (![bakedHash isKindOfClass:[NSString class]] || bakedHash.length != 64) {
        DDLogError(@"Blinkered SECURITY: master-code bridge REFUSED — this session has no baked quit hash (len %lu). A lock with nothing to compare against does not open.",
                   (unsigned long)([bakedHash isKindOfClass:[NSString class]] ? bakedHash.length : 0));
        [self blinkeredMasterCodeBridgeRefuse:reply];
        return;
    }

    // [P2R2-18] No session id ANYWHERE — neither from the page nor in home_session.json. Named, not
    // dead: without a sid there is no proof to compute, so the server could only ever see an
    // unproven quit and re-lock the device. Refusing here keeps the failure at the box the parent is
    // looking at, instead of an exit that appears to work and is undone 20 seconds later.
    NSString *fileSessionId = [homeInfo[@"sessionId"] isKindOfClass:[NSString class]] ? homeInfo[@"sessionId"] : nil;
    NSString *sessionId = pageSessionId.length > 0 ? pageSessionId : fileSessionId;
    if (sessionId.length == 0) {
        DDLogWarn(@"Blinkered: master-code bridge REFUSED — no sessionId from the page or home_session.json; no proof could be produced");
        [self blinkeredMasterCodeBridgeRefuse:reply];
        return;
    }

    // ── [P2R2-8] COMPARE IMMEDIATELY; DEFER ONLY THE REPLY ───────────────────────────────────────
    // The compare is microseconds and runs unconditionally, right here. What is throttled is the
    // ANSWER — a failed attempt is told so after ~2 s. That is the plan's own delay-not-deny rule.
    //
    // Deliberately NOT the persisted quit-throttle.json: that file denies BEFORE comparing, doubles
    // to 900 s, never decays, and is writable by the kid — so a script (or a planted file) could shut
    // the parent's own door for a quarter of an hour. And deliberately no in-memory deny state
    // either, which would just rebuild the same lockout without the file.
    if (BlinkeredExitCodeMatchesBakedHash(code, bakedHash)) {
        DDLogInfo(@"Blinkered: master-code bridge — the typed code MATCHES this session's baked hash; taking the native accept path");
        // [P2R2-15] A successful exit clears the persisted dialog lockout. A parent who has just
        // PROVEN the code must not leave a stale lockout behind for the next session — that lockout
        // exists to slow a guesser, and the guessing question has just been answered.
        [self blinkeredQuitThrottleReset];
        _blinkeredLastSwallowedQuit = nil;
        // The native Cmd+Q accept path, verbatim (§14.2 item 4).
        _blinkeredQuitMethod    = @"master_code";
        _blinkeredQuitTypedCode = code;
        _blinkeredQuitSessionId = pageSessionId.length > 0 ? pageSessionId : nil;   // [P2R2-2]
        reply(@"ok");
        dispatch_async(dispatch_get_main_queue(), ^{
            [self notifyServerQuitWithCompletion:^{ [self quitSEBOrSession]; }];
        });
        return;
    }
    DDLogInfo(@"Blinkered: master-code bridge — the typed code does not match this session's baked hash");
    [self blinkeredMasterCodeBridgeRefuse:reply];
}

// [P2R2-8] The delayed `mismatch`, with in-flight replies BOUNDED. Every refusal — wrong code or any
// of the F8 gates — lands here, so they are indistinguishable in both content and timing.
//
// Bounding, and why it is not just a counter: an unbounded stream of attempts must not become an
// unbounded stream of scheduled blocks. So refusals COALESCE onto one timer — the first arms it, the
// rest join it and are all answered together when it fires. Past the cap the answer is immediate
// (`slow-down`, which the page treats exactly as a non-match): still ANSWERED, because a bridge that
// accepts and never replies is the dead bridge [P2R2-1] exists to prevent, and self-inflicted
// flooding is the only way to reach it.
static const NSUInteger BlinkeredBridgePendingCap = 32;
- (void)blinkeredMasterCodeBridgeRefuse:(void (^)(NSString *))reply
{
    static NSMutableArray *pending;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ pending = [NSMutableArray array]; });
    @synchronized (pending) {
        if (pending.count >= BlinkeredBridgePendingCap) {
            DDLogWarn(@"Blinkered: master-code bridge — %lu replies already deferred; answering immediately",
                      (unsigned long)pending.count);
            reply(@"slow-down");
            return;
        }
        BOOL armed = pending.count > 0;
        [pending addObject:[reply copy]];
        if (armed) return;   // an earlier refusal already owns the timer — join it
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSArray *due;
        @synchronized (pending) { due = [pending copy]; [pending removeAllObjects]; }
        for (void (^r)(NSString *) in due) r(@"mismatch");
    });
}

// [P2R2-14] A page navigation clears the double-Cmd+Q latch. chromeReady is posted by every home page
// once its chrome has rendered, so it is the navigation signal we already have.
- (void)blinkeredPageChromeReady
{
    _blinkeredLastSwallowedQuit = nil;
}

// ── §2.6 native quit-dialog attempt throttling (home sessions only) ──────────
// 5 wrong entries → 60 s lockout, doubling per subsequent window, capped at 15 min. Persisted in a
// file (NOT SEB's private user defaults, which are in-memory during a session) so an app relaunch
// doesn't reset it. Defence-in-depth against grinding — the real control is the code's ~2⁵⁹ entropy.

- (NSString *)blinkeredQuitThrottlePath
{
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    return [[appSupport stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"quit-throttle.json"];
}

- (NSMutableDictionary *)blinkeredQuitThrottleState
{
    NSData *data = [NSData dataWithContentsOfFile:[self blinkeredQuitThrottlePath]];
    NSDictionary *state = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    return [state isKindOfClass:[NSDictionary class]] ? [state mutableCopy] : [NSMutableDictionary new];
}

- (void)blinkeredQuitThrottleSave:(NSDictionary *)state
{
    NSData *data = [NSJSONSerialization dataWithJSONObject:state options:0 error:nil];
    if (data) [data writeToFile:[self blinkeredQuitThrottlePath] atomically:YES];
}

// Seconds until the dialog may be shown again; 0 = not locked out.
- (NSTimeInterval)blinkeredQuitDialogLockoutRemaining
{
    NSDictionary *state = [self blinkeredQuitThrottleState];
    double lockUntil = [state[@"lockUntil"] doubleValue];
    NSTimeInterval remaining = lockUntil - [NSDate date].timeIntervalSince1970;
    return remaining > 0 ? remaining : 0;
}

- (void)blinkeredQuitThrottleRecordFailure
{
    NSMutableDictionary *state = [self blinkeredQuitThrottleState];
    NSInteger fails = [state[@"failCount"] integerValue] + 1;
    if (fails >= 5) {
        double windowSeconds = [state[@"windowSeconds"] doubleValue];
        windowSeconds = windowSeconds > 0 ? MIN(windowSeconds * 2, 900) : 60;
        state[@"windowSeconds"] = @(windowSeconds);
        state[@"lockUntil"] = @([NSDate date].timeIntervalSince1970 + windowSeconds);
        state[@"failCount"] = @0;
        DDLogWarn(@"Blinkered: home quit dialog locked out for %.0f s after repeated wrong codes", windowSeconds);
    } else {
        state[@"failCount"] = @(fails);
    }
    [self blinkeredQuitThrottleSave:state];
}

- (void)blinkeredQuitThrottleReset
{
    [[NSFileManager defaultManager] removeItemAtPath:[self blinkeredQuitThrottlePath] error:nil];
}

// ── [R1-5] §2.4 native offline panel: name the way out ───────────────────────
// Triggered (via the blinkeredHomeConnectivityFailed notification) from BOTH the load-failure path
// and the cert-challenge cancel path. Native because a stranded device can't be served a page.

- (void)blinkeredHomeConnectivityFailed:(NSNotification *)notification
{
    NSDictionary *info = notification.userInfo;
    // FIX 2 (§4). Arm the unattended self-retry on the SAME signal that raises the panel, and arm
    // it BEFORE the hop below rather than inside it.
    //
    // CONDITION 8, and this is the trap the review calls the single most likely way Fix 2 ships
    // inert: the dispatch_async on the next line is where -runModal is entered from, so once the
    // panel is up NOTHING dispatched to the main queue drains until a human presses a button. If
    // the arming rode inside that block, Fix 2 would arm only after the panel was gone — the exact
    // inertness §4.1 deleted the panel bail to prevent, reintroduced silently and invisibly.
    // The perform below is a run-loop callback in the modal modes, which is a different mechanism
    // (measured: fires at 1.00 s against a 1.0 s schedule with a modal up 0.1→3.1 s).
    if ([NSThread isMainThread]) {
        [self blinkeredHomeRetryArm];
    } else {
        [self performSelectorOnMainThread:@selector(blinkeredHomeRetryArm)
                               withObject:nil
                            waitUntilDone:NO
                                    modes:BlinkeredModalSafeRunLoopModes()];
    }
// BEGIN blinkeredOfflinePanelEnqueueGuard
    // THE PANEL IS RAISED ONCE PER OUTAGE, AND NEVER BEHIND A RAISE THAT CANNOT RUN.
    //
    // Both clauses exist because Fix 2 MANUFACTURES connectivity failures — one per attempt, every
    // 30 s for as long as the outage lasts — and the panel machinery was designed around failures
    // that a human caused. Neither clause changes anything on a device without Fix 2 armed.
    //
    // (1) R2-F3 — "is a RAISE PENDING", not "is a panel showing". The dispatch below cannot drain
    // while -runModal runs inside one of the main queue's own blocks (the probe's control arm D,
    // measured starved for the modal's whole life). Asking "is a panel showing" looked right and was
    // blind for the one window the guard was written for: the panel's completion handler clears
    // _blinkeredOfflinePanelShowing at :11561 BEFORE -requestedQuit: opens its inline nested
    // exit-code modal, so while a parent stands at that dialog fetching their Master Exit Code every
    // failure enqueues again. Three minutes there was ~6 queued raises landing on their cancel.
    // A pending flag is true from the enqueue, so it covers the whole window.
    //
    // (2) R2-F2 — once per OUTAGE. Without this, every dismissal is followed by a fresh panel within
    // ~30 s, for the whole outage: dismiss, fetch the code, come back, panel again. That is a UX
    // change nobody designed, emitted as a side effect of Fix 2, and it is the fourth instance of
    // this workstream's own pattern — a change meant to help a stranded parent making the escape
    // route worse. Turning the re-raise into a deliberate D2 affordance may well be right, but it is
    // the "much smaller alternative" from the review's A9 and it wants designing, not emitting.
    //
    // WHAT STILL RE-RAISES, because removing it would be the original bug wearing a hat:
    //   * a HUMAN pressing Retry — the panel's Retry branch clears both latches, so a retry that
    //     fails still brings the panel back, exactly as §3 C2 requires;
    //   * a NEW outage — both disarm sites clear the latch on a committed document, so a lock that
    //     loads and later fails again gets its panel.
    // What no longer re-raises is an unattended retry failing, which is the only case Fix 2 added.
    if (_blinkeredOfflinePanelRaisePending) {
        DDLogInfo(@"Blinkered: offline panel raise already pending — connectivity failure noted, not enqueued again (R2-F3)");
        return;
    }
    if (_blinkeredOfflinePanelRaisedThisOutage) {
        DDLogInfo(@"Blinkered: offline panel already raised this outage — unattended retry failure noted, panel not re-raised (R2-F2)");
        return;
    }
    _blinkeredOfflinePanelRaisePending = YES;
    dispatch_async(dispatch_get_main_queue(), ^{
        [self blinkeredMaybeShowOfflinePanel:info];
    });
// END blinkeredOfflinePanelEnqueueGuard
}

// R3-F3. The once-per-outage latch is per-OUTAGE within a session; a new session has had no outage
// and must be able to raise its first panel. Called from the [FIX2-G1] in-process session funnel,
// which is the only place one session ends and another begins without a new process.
- (void)blinkeredResetOfflinePanelOutageLatch
{
    _blinkeredOfflinePanelRaisedThisOutage = NO;
    _blinkeredOfflinePanelRaisePending = NO;
    _blinkeredOfflinePanelLastShown = nil;
    // [review F5] The R3-F3 note above lists what a session reset must clear; #77 added a fourth
    // item to that state and this is it. A retained NSAlert from a previous session would otherwise
    // survive into the next, where the identity-scoped clear can never match it.
    _blinkeredOfflinePanelAlert = nil;
}

- (void)blinkeredMaybeShowOfflinePanel:(NSDictionary *)info
{
    _blinkeredOfflinePanelRaisePending = NO;    // R2-F3: this block IS the pending raise; consume it
    if (_blinkeredOfflinePanelShowing) return;                                  // one at a time
    if (![self blinkeredHomeSessionInfo]) return;                               // only during a home lock
    if (_blinkeredOfflinePanelLastShown &&
        [[NSDate date] timeIntervalSinceDate:_blinkeredOfflinePanelLastShown] < 15) return;   // retry-loop damping
    NSWindow *mainWin = self.browserController.mainBrowserWindow;
    if (!mainWin) return;
    _blinkeredOfflinePanelShowing = YES;
    _blinkeredOfflinePanelLastShown = [NSDate date];
    _blinkeredOfflinePanelRaisedThisOutage = YES;   // R2-F2 — cleared by a human Retry or a commit

    BOOL certKind = [info[@"kind"] isEqualToString:@"cert"];
    // Self-exit locks bake no native quit password — the way out is a free, confirmed quit.
    NSString *quitHash = [[NSUserDefaults standardUserDefaults] secureObjectForKey:@"org_safeexambrowser_SEB_hashedQuitPassword"];
    BOOL selfExit = (quitHash.length == 0);

    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    NSAlert *alert = [self newAlert];
    [alert setMessageText:@"Can’t reach Blinkered on this network"];
    NSMutableString *text = [@"This network may be blocking or intercepting Blinkered (some school and public networks do). The lock can’t update here." mutableCopy];
    if (certKind) {
        // Diagnostic gold for support — and it tells the parent the device isn't broken.
        [text appendString:@"\n\nThis network appears to be inspecting secure traffic."];
    }
    if (selfExit) {
        [text appendString:@"\n\nYou can exit: press Enter Exit Code and confirm."];
    } else {
        [text appendString:@"\n\nA parent can exit this lock: get the Master Exit Code from the Blinkered parent app (Settings → Master Exit Code) on any phone, then press Enter Exit Code below (or Cmd+Q)."];
    }
    [alert setInformativeText:text];
    // The button block below is SLICED AND COMPILED by run-offline-panel-cmdq-test.sh, which drives
    // it inside a real -runModal session. Keep it self-contained: `alert` in, nothing else.
// BEGIN blinkeredOfflinePanelButtons
    // Retry FIRST — NSAlert makes the first button the window's defaultButtonCell, and that is what
    // delivers Return. Button key equivalents are a SEPARATE mechanism (Retry's own -keyEquivalent
    // stays @""), so the Cmd+Q below cannot collide with Return.
    [alert addButtonWithTitle:@"Retry"];
    NSButton *exitButton = [alert addButtonWithTitle:@"Enter Exit Code…"];
    // [D1] The informative text above promises "(or Cmd+Q)" — and that promise was FALSE for as
    // long as the panel was on screen. runModalAlert: ends in -runModal, an APP-MODAL session that
    // swallows the Cmd+Q key equivalent (3.6.197 device run: no quit alert for the 11 s the panel
    // was up, three within seconds of it being dismissed). A parent who trusts the printed
    // instruction concludes the machine is dead.
    //
    // Owning the key equivalent here makes the modal session deliver Cmd+Q to THIS button, which
    // routes to the same native quit path Cmd+Q takes when the panel is not up. The destination is
    // unchanged; the keystroke simply stops being swallowed.
    exitButton.keyEquivalent = @"q";
    exitButton.keyEquivalentModifierMask = NSEventModifierFlagCommand;
// END blinkeredOfflinePanelButtons
    [alert setAlertStyle:NSAlertStyleWarning];
    void (^offlinePanelAnswer)(NSModalResponse) = ^void (NSModalResponse answer) {
        [self removeAlertWindow:alert.window];
        _blinkeredOfflinePanelShowing = NO;
        // Identity-scoped [review F5]: today's safety is main-queue ordering between an old sheet's
        // completion handler and a new session's raise, which is true and was nowhere stated.
        if (_blinkeredOfflinePanelAlert == alert) { _blinkeredOfflinePanelAlert = nil; }
        if (answer == NSAlertFirstButtonReturn) {
            // NAVIGATE, never -reload. The load that raises this panel fails PROVISIONALLY, so the
            // webview holds no current URL and no back-forward entry and -reload is a silent no-op
            // — the reported dead end (OFFLINE_RETRY_DEAD_END_PLAN §1.1).
            //
            // Never the abstract -reload: that one is gated on isReloadAllowed, a policy about
            // whether the KID may refresh, which must not govern a parent's recovery. Since §5 C10
            // the RAW WKWebView route is the https route ONLY — a non-https signed-config target
            // (blinkered-offlinecover://) goes through -loadURL:, which carries no such gate. See
            // -blinkeredIssueRecoveryNavigation:webView: for the rule and why it is split.
            WKWebView *wk = [self blinkeredMainWebView];
            if (!wk) {
                // Bail BEFORE selecting a target. A nil receiver takes -loadRequest: silently —
                // the original bug's exact signature — and the success branch below would have
                // logged "navigating" and cleared the damping over a load that never happened,
                // which is worse than the silence. Same shape as the wake-edge probe's nil bail
                // (:3145-3149), which reports its own sentinel for the same reason.
                DDLogError(@"Blinkered: offline panel — Retry: NO main webview — cannot navigate");
                return;
            }
            NSURL *committed = wk.URL;
            NSURL *target = [SEBAbstractWebView blinkeredRecoveryTargetForCommittedURL:committed
                                                                    configuredStartURL:[SEBAbstractWebView blinkeredConfiguredStartURL]];
            if (target) {
                // Branch, never the URL — the home start URL carries the device token. The seam
                // returns one of its two inputs, so identity IS the branch.
                DDLogInfo(@"Blinkered: offline panel — Retry: navigating (target=%@)",
                          target == committed ? @"committed URL" : @"configured start URL");
                // Re-arm the panel. If this navigation also fails, the 15 s damping above must not
                // swallow the panel: a silently failed retry is the original bug wearing a hat.
                _blinkeredOfflinePanelLastShown = nil;
                // R2-F2. A HUMAN pressed this, so the once-per-outage latch is cleared with the
                // damping. The latch exists to stop Fix 2's unattended retries nagging; it must
                // never swallow the panel a parent's own press earned.
                _blinkeredOfflinePanelRaisedThisOutage = NO;
                [self blinkeredIssueRecoveryNavigation:target webView:wk];
            } else {
                // No usable committed URL and no configured start URL. Do NOT assemble one — say
                // so, so the next occurrence is one grep away rather than another device forensic.
                DDLogError(@"Blinkered: offline panel — Retry: NO navigation target (configured start URL absent)");
            }
        } else if (answer == NSAlertSecondButtonReturn) {
            DDLogInfo(@"Blinkered: offline panel — Enter Exit Code (native quit path)");
            // Same native quit flow as Cmd+Q's fallback — ONE validation surface, not two
            // (password dialog for !allowSelfExit; confirm-quit for self-exit).
            _blinkeredSkipHomeExitModal = YES;
            [self requestedQuit:nil];
            _blinkeredSkipHomeExitModal = NO;
        }
    };
    // runModalAlert raises the alert above the lockdown cover windows (capWindows → MainMenu+6),
    // the same leveling every kiosk alert uses — see the accent-popover precedent.
    // ── E1 EXPERIMENT (3.6.200). PREDICTION, recorded before the build: with the panel on screen as
    // a SHEET, Fix 2's unattended navigation COMMITS and `home retry: … DISARMED` appears with nobody
    // touching the machine — the observation three device runs and thirteen attempts never produced.
    //
    //   commits     -> the blocker is the nested modal RUN LOOP. E1 closes with this branch alone,
    //                  and BACKDROP_EXIT_SURFACE_PLAN.md is then justified by D2/D3 only.
    //   does not    -> modality was never the mechanism; §6.3's E1 diagnosis is wrong and every
    //                  design resting on "no runModal in the parent's path" rests on a refuted
    //                  hypothesis. Look at window ordering, key-window state, the covers, or WebKit
    //                  throttling under the kiosk presentation options.
    //
    // WHY A SHEET IS THE PROBE: §6.3's supporting symptom is a performSelector:afterDelay: starved
    // for four minutes that fired in the same 10 ms window as the modal ending — run-loop-MODE
    // starvation, not modality as such. A sheet runs no nested loop.
    //
    // THE RUN IS VOID IF THE SHEET IS NOT VISIBLE. Confirm it on screen before scoring anything, the
    // way §0.5's H4 refuse-to-score does. Fallback if it is invisible: the brand backdrop and Cmd+Q
    // (the 3.6.198 D1 fix) still work, so a parent is not stranded — but the affordance is gone and
    // this must be reverted.
    _blinkeredOfflinePanelAlert = alert;   // (c) — cleared in the completion handler below
    [self blinkeredRunSheetPreferringAlert:alert forWindow:mainWin completionHandler:offlinePanelAnswer];
}


#pragma mark - Blinkered Fix 2: a locked device retries connectivity by itself

// Markers, not a heuristic: run-home-retry-modal-safety-test.sh scopes its checks to THIS region,
// and a gate that guesses where a module ends is a gate that stops covering the lines added after it.
// BEGIN blinkeredHomeRetryModule

// OFFLINE_RETRY_DEAD_END_PLAN §4. A home lock whose page failed to load retries the SIGNED CONFIG's
// start URL on its own, until it succeeds, so a device whose network comes back recovers with
// nobody touching it.
//
// WHY IT EXISTS, concretely (§6.2 D2). On 19 Aug a parent sat in front of a locked Mac that was
// fully online, with a lock page that would have loaded, and no way to make it load. The panel is
// raised only by a load FAILURE, so once it has been dismissed nothing navigates, nothing fails,
// and no panel returns — a branded lock screen with no affordance at all. Fix 1 gave the Retry
// button a navigation that works; it still needs a human to press it. This is the half that does
// not.
//
// WHAT IT IS ALLOWED TO DO, and why that does not weaken the lock (§4.4):
//   • it navigates ONLY to the start URL of the signed config — page content cannot author
//     org_safeexambrowser_SEB_startURL, and the target comes from the same seam the panel's Retry
//     and the wake-edge reload use, so what we navigate and what the interceptors authorise are one
//     function of one input;
//   • it cannot be triggered BY page content: it fires only when the page is ABSENT;
//   • it touches no Wi-Fi state, no menu-bar shield, no presentation options, no window levels;
//   • the unlock-window replay it could otherwise provoke is refused by the shipped, mutation-tested
//     write guard PLUS the fire-time G2 re-read below — see the gate block for the full statement.
//
// THREE THINGS ARE LOAD-BEARING AND ARE EASY TO "TIDY" AWAY:
//   1. every main-thread wake-up here goes through BlinkeredModalSafe* — see the measurement table
//      at the top of this file. A dispatch_after(main) anywhere on this path ships Fix 2 inert;
//   2. the gates are re-read in the fire callback, never at arm time (condition 2 / obligation 3-a);
//   3. there is NO _blinkeredOfflinePanelShowing bail here, and its absence is the feature
//      (condition 4). See blinkeredHomeRetryFire.

// F7. A SKIPPED attempt tested a gate, not the network, so it must not spend the fast end of the
// ramp — the hold-black gate alone is up for ~16 s on an offline boot (rig §6.2 measured the reveal
// at 15.98 s), which used to consume 2, 5 and 10 before the feature was even eligible to navigate.
// But a gate that stays shut must not leave the app re-checking every 2 s forever either, so the
// fast re-check is bounded and then falls to the steady-state floor. Both numbers are chosen to
// cover that measured 16 s with margin and nothing more.
static const NSTimeInterval kBHRSkipRecheck  = 2.0;
static const NSUInteger     kBHRMaxFastSkips = 12;   // 24 s of fast re-checks, then the 30 s floor

// The backoff floor. A satisfied network path is not a reachable server, so the timer runs whether
// or not NWPathMonitor has anything to say — and deliberately is NOT gated on path status, because
// the failure this whole workstream keeps producing is a feature that cannot fire. A monitor that
// is wrong about an odd link (captive portal, USB tether, a VPN coming up) then costs latency, not
// recovery.
static const NSTimeInterval kBHRBackoff[]  = { 2.0, 5.0, 10.0, 20.0, 30.0 };
static const NSUInteger     kBHRBackoffSteps = sizeof(kBHRBackoff) / sizeof(kBHRBackoff[0]);
static const NSTimeInterval kBHRSteadyState  = 30.0;   // …then every 30 s, indefinitely (see below)
// CONDITION 6. `.satisfied` fires on link-up, before DHCP and DNS have settled, so the first
// path-triggered attempt waits. Short enough that the acceptance run still looks instant.
static const NSTimeInterval kBHRPathSettleDelay = 1.5;
// CONDITION 5. How long a recovery navigation counts as in flight. See -blinkeredNavigationInFlight
// for why this is a DEADLINE and not a BOOL.
//
// F10 — THIS NUMBER IS A HEURISTIC AND IS RECORDED AS ONE. The wake edge's probe chain is described
// elsewhere in this file as running up to ~11 s, and that duration has never been measured; 12 s
// leaves about a second of margin against a figure nobody has checked. Both directions are bounded
// and neither can strand a device: too short and the wake edge stops seeing a retry it should have
// deferred to (it then spends one of six session reload slots), too long and a retry that takes more
// than 12 s to commit can be navigated over by the next fire. Widening it is cheap; do it from a
// measurement of the chain, not from this comment.
static const NSTimeInterval kBHRInFlightWindow = 12.0;

static BOOL              _blinkeredHomeRetryArmed = NO;
static NSUInteger        _blinkeredHomeRetryStep = 0;          // index into kBHRBackoff
static NSUInteger        _blinkeredHomeRetrySkips = 0;         // consecutive gate-closed re-checks (F7)
static BOOL              _blinkeredHomeRetryObserverInstalled = NO;   // F2 — see -blinkeredHomeRetryArm
static BOOL              _blinkeredNavigationInFlightIsHomeRetry = NO; // F9 — whose mark is it?
static NSInteger         _blinkeredHomeRetryNavigations = 0;   // per session; reset with the wake edge's
static NSTimeInterval    _blinkeredHomeRetryNextFireAt = 0;    // 0 = nothing pending
static NSTimeInterval    _blinkeredNavigationInFlightUntil = 0;
static nw_path_monitor_t _blinkeredHomeRetryPathMonitor = nil;
static dispatch_queue_t  _blinkeredHomeRetryPathQueue = nil;
static BOOL              _blinkeredHomeRetryPathSatisfied = NO;   // written and read ONLY on that queue

// THERE IS NO HARD SESSION CAP, and that is a decision, not an omission.
//
// v1's G5 was "a hard cap per session mirroring kBWEMaxReloadsSession". It is not among the ten
// consolidated conditions in §4.5, and taken literally it reintroduces the dead end Fix 2 exists to
// end: a device out of range for an hour would spend a six-attempt budget in the first two minutes
// and then be exactly as stranded as before, with a green gate over it. The acceptance test —
// force-reboot out of range, leave it alone, walk back into range, touch nothing — is a test of
// what happens after an ARBITRARY delay, so the retry has to still be alive then.
//
// What bounds it instead is the RATE (30 s in steady state) and the gates, every one of which is
// re-read per attempt. An attempt costs a file read, a back-forward-list read and one navigation of
// the signed start URL that fails provisionally; it cannot install anything, and the one write it
// could provoke is refused. The per-session counter below is a budget in the sense condition 5
// means — state that resets in -blinkeredArmPaintRecovery with the wake edge's — and it is read in
// the logs, not as a ceiling.

// ── The shared in-flight flag (condition 5 / review F11 scenario A) ───────────────────────────
//
// A DEADLINE, NOT A BOOL, and the difference is the failure mode. A bool needs a clearing edge, and
// the only clearing edges available here are WebKit callbacks this class does not receive; a
// clearing path that breaks leaves the flag stuck YES, which silently disables BOTH recovery
// navigators — the wake-edge wedge reload and this retry — permanently, for the rest of the
// session, on a locked child's machine. That is the inertness class this workstream has shipped
// twice. A deadline cannot get stuck: the worst a bug can do is suppress recovery for
// kBHRInFlightWindow seconds and then it self-clears.
- (BOOL)blinkeredNavigationInFlight
{
    return _blinkeredNavigationInFlightUntil > [NSDate timeIntervalSinceReferenceDate];
}

- (void)blinkeredNoteRecoveryNavigationIssued
{
    _blinkeredNavigationInFlightUntil = [NSDate timeIntervalSinceReferenceDate] + kBHRInFlightWindow;
    // Default to "not ours": only the retry's own fire path claims it, on the line after it calls
    // through this seam. Panel Retry and the wake-edge reload leave it NO (F9).
    _blinkeredNavigationInFlightIsHomeRetry = NO;
}

// ── The per-session reset, and WHO IS ALLOWED TO CALL IT ───────────────────────────────────────
//
// Split into a policy function so run-home-retry-modal-safety-test.sh can slice it and drive the
// SHIPPED decision under a real modal session (probe arm G). The decision is one line; the reason
// it needs its own probe arm is that its CALLER is two thousand lines away and arrives late.
// F1 — A ONE-SHOT LAUNCH TIMER MUST NOT BE ABLE TO SWITCH THIS FEATURE OFF.
//
// The caller that matters is not the one this reset was written for. -blinkeredArmPaintRecovery is
// reached from exactly one place: -performAfterStartActions:'s
// `performSelector:@selector(performAfterStartActions:) … afterDelay:2` — a DEFAULT-MODE perform,
// scheduled immediately after the start-URL load is kicked off, and the very mechanism §4.2's table
// calls row 3. On an offline boot the -1009 lands at ~1.26 s (rig §6.2), so by the time that perform
// comes due the retry is ARMED and the offline panel is UP — and a default-mode perform is starved
// for the panel's entire life. It fires the instant a human dismisses the panel.
//
// What that cost, before this guard: the reset disarmed the retry, and NOTHING re-arms it. The only
// re-arm is -blinkeredHomeConnectivityFailed:, which needs a load failure, which needs a navigation
// — and after "Enter Exit Code… → cancel" there is no navigation. Carry the Mac back into range and
// nothing happens. That is plan §6.2 D2 verbatim: the one state Fix 2 exists for was the one state
// it was guaranteed to be off in.
//
// MEASURED, not reasoned about. run-home-retry-modal-safety-test.sh arm G replays the launch order
// and drives the policy below under a real -runModal session. Before this guard it reported the
// starved perform firing 19 ms after the modal ended and disarming an armed retry — the same shape
// as the three device observations already recorded at SEBBrowserWindow.m:1543 ("43.2 s, 16.1 s and
// 205 s … every one within 261 ms of the user pressing Retry"). That comment was in this repo the
// whole time; STAGE 3 fixed the perform it was chasing and did not sweep the file.
//
// WHY NOT FIX -performAfterStartActions: INSTEAD. Giving it the modal modes changes when performAfterStartActions runs —
// kiosk reinforcement, the app-switcher check — inside a modal session, on the highest-traffic path
// in the product, to fix a bug in this feature. The sweep of the other nine default-mode performs is
// recorded in the build report; -performAfterStartActions: is deliberately NOT among the ones converted.
//
// CONDITION 5 IS STILL MET. The reset still happens in one place and still resets Fix 2's ramp,
// counter and shared deadline alongside the wake edge's budgets. What it no longer does is treat a
// LIVE retry as stale per-session state. Teardown has its own unconditional cancel — see
// -blinkeredHomeRetryCancelForTeardown, which exists because this guard would otherwise let an
// armed retry outlive the session (F8).
// BEGIN blinkeredHomeRetryResetPolicy
static BOOL BlinkeredHomeRetryResetMayDisarm(BOOL retryArmed)
{
    return !retryArmed;
}
// END blinkeredHomeRetryResetPolicy

// BEGIN blinkeredHomeRetryResetForSession
- (void)blinkeredHomeRetryResetForSession
{
    if (!BlinkeredHomeRetryResetMayDisarm(_blinkeredHomeRetryArmed)) {
        DDLogWarn(@"Blinkered home retry: per-session reset DECLINED — a retry is armed and this "
                  @"caller is a launch timer arriving late, not a new session (F1)");
        return;
    }
    BlinkeredModalSafeCancelPerform(self, @selector(blinkeredHomeRetryFire));
    _blinkeredHomeRetryArmed = NO;
    _blinkeredHomeRetryStep = 0;
    _blinkeredHomeRetrySkips = 0;
    _blinkeredHomeRetryNavigations = 0;
    _blinkeredHomeRetryNextFireAt = 0;
    _blinkeredNavigationInFlightUntil = 0;
    _blinkeredNavigationInFlightIsHomeRetry = NO;
}
// END blinkeredHomeRetryResetForSession

// F8. Teardown must cancel unconditionally, and the reset above no longer can: it now declines
// precisely when the retry is armed, which is the state teardown finds it in. G1 already refuses the
// navigation, so this was never a navigation hazard — but without it the comment at the call site
// was a promise rather than a mechanism, and an armed retry would go on rescheduling every 30 s
// through a session that no longer exists.
- (void)blinkeredHomeRetryCancelForTeardown
{
    if (!_blinkeredHomeRetryArmed) return;
    _blinkeredHomeRetryArmed = NO;
    BlinkeredModalSafeCancelPerform(self, @selector(blinkeredHomeRetryFire));
    _blinkeredHomeRetryNextFireAt = 0;
    DDLogInfo(@"Blinkered home retry: cancelled for teardown");
}

// ── Arming ────────────────────────────────────────────────────────────────────────────────────
//
// Armed by the SAME signal that raises the offline panel: a main-frame load failure of our own
// content, with a connectivity-class error, during a home session
// (-[SEBAbstractWebView blinkeredOfflinePanelForLoadError:]). Arming on that signal rather than on
// a timer is what keeps this scoped — Fix 2 by construction only ever runs after a failure.
- (void)blinkeredHomeRetryArm
{
    [self blinkeredHomeRetryStartPathMonitorIfNeeded];
    [self blinkeredHomeRetryInstallCommitObserverIfNeeded];
    // F9. Clear the in-flight mark only if it is OURS. The deadline is shared with the wake-edge
    // wedge reload (condition 5), and this method runs on EVERY connectivity failure — including one
    // from a load the wake edge issued. Clearing it blind would strip the other navigator's mark and
    // defeat the mutual exclusion the flag exists for. Clearing our own is what keeps the 2/5/10 ramp
    // from being swallowed whole by in-flight skips.
    if (_blinkeredNavigationInFlightIsHomeRetry) {
        _blinkeredNavigationInFlightUntil = 0;
        _blinkeredNavigationInFlightIsHomeRetry = NO;
    }
    if (_blinkeredHomeRetryArmed) {
        // One of our own retries failing, or a second failure for the same outage. Do NOT restart
        // the ramp: the fire path owns the schedule, and re-arming to 2 s on every failure would
        // turn the backoff into a fixed 2 s loop.
        return;
    }
    _blinkeredHomeRetryArmed = YES;
    _blinkeredHomeRetryStep = 0;
    DDLogWarn(@"Blinkered home retry: ARMED — the home lock page failed to load; this device will retry the signed start URL on its own until it loads");
    [self blinkeredHomeRetryScheduleIn:[self blinkeredHomeRetryTakeNextDelay] reason:@"arm"];
}

// F2. The commit-prompt observer must NOT live inside the paint-recovery lifecycle.
//
// It used to be registered in -blinkeredArmPaintRecovery, after that method's
// `if (_blinkeredPaintArmed) return;`. But -blinkeredArmPaintRecovery is reached only from the
// starved launch timer of F1, so for the entire period the offline panel is up NO OBSERVER EXISTS —
// and that period is exactly when Fix 2 is armed. The prompt disarm, which was written to close a
// real mid-navigation defect, was therefore dead code in the acceptance scenario, with no on-screen
// symptom to reveal it (the backdrop still came down, because -sebWebViewDidCommitLoad drops it
// unconditionally). Fixing F1 does NOT fix this: the reset declining to disarm does not make the
// starved method run any earlier. It needed its own fix, and this is it.
//
// Installed once per process, from the arming path, which by construction runs while the panel is
// up. The handler already early-returns on !_blinkeredHomeRetryArmed, so leaving it installed for
// the process costs one branch per commit.
- (void)blinkeredHomeRetryInstallCommitObserverIfNeeded
{
    if (_blinkeredHomeRetryObserverInstalled) return;
    _blinkeredHomeRetryObserverInstalled = YES;
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(blinkeredContentCommitted:)
                                                 name:@"BlinkeredContentCommitted" object:nil];
    DDLogInfo(@"Blinkered home retry: commit-prompt observer installed");
}

- (NSTimeInterval)blinkeredHomeRetryTakeNextDelay
{
    NSTimeInterval delay = (_blinkeredHomeRetryStep < kBHRBackoffSteps)
                         ? kBHRBackoff[_blinkeredHomeRetryStep] : kBHRSteadyState;
    if (_blinkeredHomeRetryStep < kBHRBackoffSteps) _blinkeredHomeRetryStep++;
    return delay;
}

// MAIN THREAD ONLY. Keeps one pending wake-up, and never lets a later one push an earlier one out.
- (void)blinkeredHomeRetryScheduleIn:(NSTimeInterval)delay reason:(NSString *)reason
{
    NSTimeInterval fireAt = [NSDate timeIntervalSinceReferenceDate] + delay;
    if (_blinkeredHomeRetryNextFireAt > 0 && fireAt >= _blinkeredHomeRetryNextFireAt) {
        return;   // something sooner is already pending — a path edge must never DELAY a backoff
    }
    BlinkeredModalSafeCancelPerform(self, @selector(blinkeredHomeRetryFire));
    _blinkeredHomeRetryNextFireAt = fireAt;
    BlinkeredModalSafePerform(self, @selector(blinkeredHomeRetryFire), delay);
    DDLogInfo(@"Blinkered home retry: next attempt in %.1f s (%@)", delay, reason);
}

// ── CONDITION 9 — the queue is the safety property, not NWPathMonitor ──────────────────────────
//
// nw_path_monitor_set_queue takes whatever it is handed, and pointed at the MAIN queue it was
// measured starved for the modal's entire life (row 5 of the table at the top of this file). So the
// private serial queue below is a binding condition, not an implementation detail.
//
// The monitor is started once and never cancelled: a start/stop lifecycle is one more thing that
// can be left in the wrong state, and the handler is a status read plus one early return when the
// retry is not armed. It costs nothing to leave running.
- (void)blinkeredHomeRetryStartPathMonitorIfNeeded
{
    if (_blinkeredHomeRetryPathMonitor) return;
    _blinkeredHomeRetryPathQueue = dispatch_queue_create("app.blinkered.home-retry-path", DISPATCH_QUEUE_SERIAL);
    _blinkeredHomeRetryPathMonitor = nw_path_monitor_create();
    nw_path_monitor_set_queue(_blinkeredHomeRetryPathMonitor, _blinkeredHomeRetryPathQueue);
    nw_path_monitor_set_update_handler(_blinkeredHomeRetryPathMonitor, ^(nw_path_t path) {
        // Runs on the private queue. _blinkeredHomeRetryPathSatisfied is confined to it.
        BOOL satisfied = (nw_path_get_status(path) == nw_path_status_satisfied);
        BOOL wasSatisfied = _blinkeredHomeRetryPathSatisfied;
        _blinkeredHomeRetryPathSatisfied = satisfied;
        if (!satisfied || wasSatisfied) return;   // only the unsatisfied → satisfied EDGE
        DDLogInfo(@"Blinkered home retry: network path became satisfied");
        // CONDITION 8, the mandatory hop. Never dispatch_async(main) — see BlinkeredModalSafeHopToMain.
        BlinkeredModalSafeHopToMain(self, @selector(blinkeredHomeRetryPathBecameSatisfied));
    });
    nw_path_monitor_start(_blinkeredHomeRetryPathMonitor);
    DDLogInfo(@"Blinkered home retry: network path monitor started on a private serial queue");
}

- (void)blinkeredHomeRetryPathBecameSatisfied
{
    if (!_blinkeredHomeRetryArmed) return;
    // A new connectivity episode: this is the edge that would have recovered the device unattended,
    // so go back to the fast end of the ramp rather than carrying an hour of backoff into it.
    _blinkeredHomeRetryStep = 0;
    [self blinkeredHomeRetryScheduleIn:kBHRPathSettleDelay reason:@"path satisfied"];
}

// ── The fire callback ─────────────────────────────────────────────────────────────────────────
//
// Reached only through BlinkeredModalSafePerform, so it runs on the main thread in whichever of the
// three modes is current — INCLUDING NSModalPanelRunLoopMode, i.e. with the offline panel up. That
// is the point.
- (void)blinkeredHomeRetryFire
{
    _blinkeredHomeRetryNextFireAt = 0;
    if (!_blinkeredHomeRetryArmed) return;

// BEGIN blinkeredHomeRetryGates
    // ══ CONDITION 2, and with it obligation 3-a ══════════════════════════════════════════════
    // EVERY gate below is evaluated HERE, in the same run-loop callback that issues the navigation
    // a few lines further down — never at arm time. Precedent: the wake-edge probe chain's
    // "re-check the gates that can flip mid-chain" at :3418-3427, for the same reason (an overdue
    // unlock is delivered on exactly the edge that wakes this path).
    //
    // THE G2 RE-READ IS WHAT MAKES FIX 2 SAFE, so read this before weakening it.
    // -blinkeredHomeSessionInfo is a per-call read of home_session.json. During the unlock window
    // the agent has DELETED that file while this app is still running, so G2 is nil throughout and
    // Fix 2 does not fire there at all — which is why Fix 2 needs no suppression code of its own
    // and must not grow any. Behind it, structurally, is the shipped refresh-or-first-write guard
    // (+[SEBAbstractWebView blinkeredHomeSessionWriteDecision…]): the write sits inside
    // -decidePolicyForNavigationAction:, which WebKit calls to AUTHORISE a navigation and therefore
    // before that navigation can fail, so the very first start-URL navigation of the process arms
    // the latch even on the offline boot where it fails provisionally — and Fix 2 by construction
    // only fires AFTER such a failure. File absent + latch armed ⇒ SkipReplay.
    // It is the re-read PLUS the guard, not either alone. Move any of these gates to arm time and
    // the unlock-window replay reopens.
    // An app-side one-shot "this navigation is ours" flag is NOT the answer and must not be added:
    // that shape is ambient, consumable by any /seb-sethomesession navigation including one page
    // content authors, and it has already earned a BLOCKER on this workstream
    // (OFFLINE_RETRY_FIX2_G1_REVIEW F1-F5).

    // G1 — never during teardown or with a quit in flight. Sparkle's pending quit shares
    // `quittingMyself`; the agent's unlock chain sets the teardown flag.
    if (BlinkeredTeardownStarted() || self.quittingMyself) {
        DDLogInfo(@"Blinkered home retry: attempt skipped — teardown or quit in flight (G1)");
        [self blinkeredHomeRetryScheduleAfterSkip];
        return;
    }
    // G4 + the HOLD-BLACK GATE, which condition 4 keeps unchanged. -blinkeredPaintLockActive is
    // sessionRunning && !_isAACEnabled && a main window exists && the window is NOT deliberately
    // held black until first paint. Fix 2's trigger is a load failure and a load failure can land
    // DURING the hold (review F12), so this is a real gate here and not borrowed hygiene.
    if (![self blinkeredPaintLockActive]) {
        DDLogInfo(@"Blinkered home retry: attempt skipped — no live lock window, AAC, or content still held black (G4 + hold-black)");
        [self blinkeredHomeRetryScheduleAfterSkip];
        return;
    }
    // G2 — home lock only, re-read from disk at fire time. See the block comment above.
    if (![self blinkeredHomeSessionInfo]) {
        DDLogInfo(@"Blinkered home retry: attempt skipped — no home session on disk (G2; this is also the unlock window)");
        [self blinkeredHomeRetryScheduleAfterSkip];
        return;
    }
    // CONDITION 5 — the other navigator, or one of our own attempts, is still in flight.
    if ([self blinkeredNavigationInFlight]) {
        DDLogInfo(@"Blinkered home retry: attempt skipped — a recovery navigation is already in flight");
        [self blinkeredHomeRetryScheduleAfterSkip];
        return;
    }
    // G3 — CONDITION 1. "No committed URL", from the commit-derived signal §5 STAGE 3 already
    // built; NOT the rAF `nosignal` probe, which reads "no signal" on a perfectly good page that
    // simply never set the stamp and would have had Fix 2 navigate over live content.
    SEBBrowserWindow *win = self.browserController.mainBrowserWindow;
    if (![win blinkeredWebViewDefinitelyHoldsNoCommittedDocument]) {
        if ([win blinkeredWebViewDefinitelyHoldsCommittedDocument]) {
            DDLogWarn(@"Blinkered home retry: the lock page is UP (a document is committed) — disarming after %ld navigation(s)",
                      (long)_blinkeredHomeRetryNavigations);
            _blinkeredHomeRetryArmed = NO;
            [self blinkeredDismissOfflinePanelSheetIfAny];   // C1 — BOTH disarm sites, review F1
            _blinkeredOfflinePanelRaisedThisOutage = NO;   // R2-F2 — the outage is over
            // The lock page loaded while the empty-content backdrop may still be over it. This call
            // only ever REMOVES, and only on a positively committed document, so it cannot uncover
            // an empty webview (§5 C6-C10). It matters here specifically because the backdrop's own
            // liveness re-check rides _blinkeredPaintTimer, a default-mode NSTimer, which is starved
            // for as long as the offline panel is up — so without this line an unattended recovery
            // under the panel would load the page and leave the curtain over it.
            [win blinkeredRecheckEmptyContentBackdrop];
            return;
        }
        // Unknown. A true answer here ISSUES A NAVIGATION, so unknown must not fire: reloading a
        // working lock page under a child on a 30-second timer is a worse outage than waiting.
        DDLogInfo(@"Blinkered home retry: attempt skipped — committed-document signal is UNKNOWN (G3 fail-safe)");
        [self blinkeredHomeRetryScheduleAfterSkip];
        return;
    }
    // ══ NO _blinkeredOfflinePanelShowing BAIL HERE — CONDITION 4, AND ITS ABSENCE IS THE FEATURE ══
    // The original condition asked for one, mirroring the wake edge's at :3391. Taken literally it
    // makes Fix 2 inert in exactly the case it exists for: that flag is set when the panel is
    // raised and cleared in ONE place, the panel's own completion handler, which runs only when a
    // human ends the modal session. No human, no clear — indefinitely. F11 scenario B, the reason
    // the bail was asked for, is closed WITHOUT it by the "one at a time" early return in
    // -blinkeredMaybeShowOfflinePanel:, which already prevents a failed retry from re-raising the
    // panel. Leaving the panel untouched on a failed retry is therefore existing behaviour, not a
    // guard to build.
    //
    // [3.6.201] SUPERSEDED — Fix 2 now DOES dismiss the panel when the lock page COMMITS. This
    // paragraph used to say it did not, on the grounds that dismissal is "a UX repair, not a
    // correctness requirement — the device is recovered either way". **3.6.200 made that false**: the
    // panel became a sheet (which is what closed E1), and a sheet is DOCUMENT-MODAL, so the device
    // healed and stayed UNUSABLE until a human dismissed it — device-confirmed,
    // OFFLINE_RETRY_DEAD_END_PLAN §6.4.1.
    //
    // The hazard the old paragraph named was real and is now structurally gone: -abortModal ends the
    // INNERMOST modal session, which after "Enter Exit Code…" is the dialog the parent is typing into.
    // The dismissal uses -endSheet:, which names ONE sheet on ONE window and cannot reach a separate
    // app-modal session. For what actually makes that safe — the ARGUMENT, not the guard, which is
    // NOT an identity check — see the block above -blinkeredDismissOfflinePanelSheetIfAny. An earlier
    // version of this sentence claimed the guard supplied identity; it does not, and that claim is
    // what let a mutation through the gate. Do not restate it here.
    //
    // COMMITTED, NOT "SUCCESSFUL" — the words are not synonyms and the difference is a real case.
    // The disarm predicate is backForwardList.currentItem != nil, so an HTTP error body commits, and
    // so does a school filter's block page served over a trusted root — the very case this panel's
    // own copy names ("some school and public networks do"). There, the recovery disarms, this
    // dismisses, and the child is left on the block page with no Retry button. Cmd+Q (the 3.6.198 D1
    // fix) still works, so nobody is stranded, and the disarm itself predates 3.6.201 — this removes
    // an affordance in a case that was already unrecovered. Not observed on a device; do not let a
    // green run absorb it. Signal 2's fidelity is a rig question — see the "WHAT IS STILL NOT
    // CONFIRMED" block above -blinkeredCommittedDocumentSignal in SEBBrowserWindow.m — and
    // tightening the predicate does not belong in a dismissal patch — it has three call sites with
    // three different fail-safe directions.
    //
    // Still true and still load-bearing: a retry that does NOT commit leaves the panel alone. The
    // dismissal lives on the disarm path, which only a commit reaches.
// END blinkeredHomeRetryGates

    WKWebView *wk = [self blinkeredMainWebView];
    if (!wk) {
        // Bail BEFORE selecting a target: a nil receiver takes -loadRequest: silently, which is the
        // original bug's exact signature, and the counter and log line below would then claim a
        // navigation that never happened. Same shape as the panel Retry's nil bail.
        DDLogError(@"Blinkered home retry: NO main webview — cannot navigate");
        [self blinkeredHomeRetryScheduleAfterSkip];
        return;
    }
    // Committed URL deliberately nil: G3 has just established there ISN'T one, and §4.4 scopes this
    // feature to the signed config's start URL. Routed through the shared seam rather than a bare
    // pref read so what we navigate and what the start-URL interceptors authorise stay one function
    // of one input (§3.1).
    NSURL *target = [SEBAbstractWebView blinkeredRecoveryTargetForCommittedURL:nil
                                                           configuredStartURL:[SEBAbstractWebView blinkeredConfiguredStartURL]];
    if (!target) {
        DDLogError(@"Blinkered home retry: NO navigation target (configured start URL absent) — nothing to retry");
        [self blinkeredHomeRetryScheduleAfterSkip];
        return;
    }
    // R2-F8. Ask the seam whether it ISSUED anything, and count, stamp and log only if it did.
    // Its third exit — non-https target, abstract webview unreachable — navigates nothing; claiming
    // otherwise would log and count a navigation that did not happen and, worse, stamp OUR ownership
    // over an in-flight deadline that may be the WAKE EDGE's, so the next connectivity failure would
    // clear the wake edge's mark. That is the exact defeat F9's ownership flag exists to prevent.
    if (![self blinkeredIssueRecoveryNavigation:target webView:wk]) {
        DDLogError(@"Blinkered home retry: the recovery seam issued no navigation — nothing was retried");
        [self blinkeredHomeRetryScheduleAfterSkip];
        return;
    }
    _blinkeredHomeRetryNavigations++;
    _blinkeredNavigationInFlightIsHomeRetry = YES;   // F9 — the mark the shared seam just set is ours
    // THE ACCEPTANCE DISCRIMINATOR IS IN THIS LINE. `panel=UP` on an attempt is the on-device proof
    // that conditions 4 and 8 both hold: the bail is gone AND the wake-up survived the modal. A run
    // in which every attempt says `panel=down` is Fix 2 shipping inert with a green gate over it —
    // which is how §5 STAGE 2 shipped.
    DDLogWarn(@"Blinkered home retry: NAVIGATING the signed start URL unattended (attempt %ld, panel=%@)",
              (long)_blinkeredHomeRetryNavigations, _blinkeredOfflinePanelShowing ? @"UP" : @"down");
    [self blinkeredHomeRetryScheduleNext];
}

- (void)blinkeredHomeRetryScheduleNext
{
    _blinkeredHomeRetrySkips = 0;
    [self blinkeredHomeRetryScheduleIn:[self blinkeredHomeRetryTakeNextDelay] reason:@"backoff"];
}

// F7. A gate refused this attempt, so the ramp is untouched — re-check soon, but boundedly.
- (void)blinkeredHomeRetryScheduleAfterSkip
{
    _blinkeredHomeRetrySkips++;
    BOOL fast = (_blinkeredHomeRetrySkips <= kBHRMaxFastSkips);
    [self blinkeredHomeRetryScheduleIn:(fast ? kBHRSkipRecheck : kBHRSteadyState)
                                reason:(fast ? @"gate closed — re-check" : @"gate closed — settled to the floor")];
}

// ── Disarm promptly when the page actually loads, not at the next tick ─────────────────────────
//
// WHY THIS IS NOT TIDINESS. The fire path disarms on a committed document, but the next tick can be
// 30 s away, so without this the retry stays armed for up to half a minute AFTER the lock page is
// up. In that window G3 can legitimately read ABSENT again: signal 2 is the back-forward list, and
// -[SEBAbstractWebView sebWebViewDidStartLoad] CLEARS that list on every navigation start in a
// session where back/forward browsing is off — which a lock is. So a fire landing while the CHILD
// is mid-navigation would read "nothing committed", navigate the start URL, and yank them back to
// the home page from wherever they were going. The kBHRInFlightWindow deadline covers the first
// 12 s of that window and nothing covers the rest. This closes it.
//
// THE NOTIFICATION IS A PROMPT, NEVER A VERDICT. It is posted by EVERY SEBBrowserWindow, and the
// 19 Aug rig run established that isMainBrowserWindow cannot be trusted at commit time — so the
// sender is ignored entirely and the decision re-reads the main window's own signal, the same one
// the fire path uses. Consequences of that choice, both stated: a spurious notification cannot
// disarm anything (the signal still has to say Present), and a lost notification cannot make Fix 2
// inert (the fire path still disarms, just later). Neither direction can strand a device.
- (void)blinkeredContentCommitted:(NSNotification *)n
{
    if (!_blinkeredHomeRetryArmed) return;
    SEBBrowserWindow *win = self.browserController.mainBrowserWindow;
    // R3-F5. THE ONE LINE THAT MAKES CONDITION 5 AN OBSERVATION INSTEAD OF AN INFERENCE.
    //
    // Without it this handler returns silently when the signal is not Present, so a build in which
    // the observer is installed, correct and INERT emits nothing at all — and the only evidence left
    // is the absence of the DISARMED line, which is exactly the inference the review forbade. The
    // -sebWebViewDidCommitLoad log cannot substitute: it prints the signal of the window that
    // COMMITTED, this decides on the MAIN window's, and the (main window)/(site window) tag that
    // would reconcile them is the one the 19 Aug rig proved unreliable. Two different reads.
    DDLogInfo(@"Blinkered home retry: commit prompt — main window backForward=%@",
              [win blinkeredCommittedDocumentSignalDescription]);
    if (![win blinkeredWebViewDefinitelyHoldsCommittedDocument]) return;
    _blinkeredHomeRetryArmed = NO;
    _blinkeredOfflinePanelRaisedThisOutage = NO;   // R2-F2 — the outage is over
    BlinkeredModalSafeCancelPerform(self, @selector(blinkeredHomeRetryFire));
    _blinkeredHomeRetryNextFireAt = 0;
    DDLogWarn(@"Blinkered home retry: the lock page committed — DISARMED after %ld unattended navigation(s)",
              (long)_blinkeredHomeRetryNavigations);
    [win blinkeredRecheckEmptyContentBackdrop];

    [self blinkeredDismissOfflinePanelSheetIfAny];
}
// END blinkeredHomeRetryModule



// ── [3.6.201] DISMISS THE OFFLINE PANEL SHEET ───────────────────────────────────────────────────
//
// WHY IT EXISTS. 3.6.200 made the panel a SHEET, which is what closed E1 — the lock page now commits
// with the panel on screen (§6.4, 1.08 s, device-confirmed). But a sheet is DOCUMENT-MODAL: it blocks
// its parent window. So the device healed and stayed UNUSABLE until a human dismissed it. Observed on
// Maggie B's kids Mac — "the header bar is greyed out and I can't tap anything on it" — while every
// log signal was green.
//
// WHY IT IS A METHOD AND NOT INLINE [review F1 — BLOCKER]. There are TWO sites that disarm on a
// committed document: this notification path, and the retry's own FIRE path. The first version put
// the dismissal only on the notification. The fire path would then heal the device, disarm, drop the
// backdrop — and leave the sheet up. That is 3.6.200's failure verbatim, with a green log.
//
// The asymmetry made it worse than a race: the fire path is delivered by BlinkeredModalSafePerform in
// the modal run-loop modes SPECIFICALLY so it survives what starves main-queue delivery, while this
// notification is exactly the delivery §6.4 measured as starved. **The path that survives adversity
// was the one that did not dismiss.** And the fire path already carries
// blinkeredRecheckEmptyContentBackdrop for that very reason, stated in its own comment.
//
// (a) [v2 review] The original hazard was -abortModal ending the INNERMOST modal session, which after
//     "Enter Exit Code…" is the dialog the parent is typing into. What makes this safe is the
//     ARGUMENT, not the guard: -[sheetParent endSheet:panelWindow] can only ever end OUR alert's
//     window, and -endSheet: on a window that is not that parent's sheet is a no-op. The guard is
//     NOT an identity check — on the macOS 11 deployment target the parent's quit dialog sheets onto
//     the same window and returns the same sheetParent. The first version of this comment claimed
//     the guard provided identity; it does not, and that error is what let a mutation through.
// (b) "Deliver on a modal-mode run-loop callback, never a main-queue dispatch" is dissolved FOR THE
//     PANEL'S OWN PRESENTATION — there is no nested loop while only the sheet is up. It is NOT
//     dissolved generally: the parent's exit dialog at :10779 is still [NSApp runModalForWindow:].
//     C1 (calling from the fire path too) is what covers that, not this comment.
// (c) _blinkeredOfflinePanelAlert, set at the raise, cleared identity-scoped in the completion
//     handler and in the session reset funnel.
//
// The return code is deliberately NEITHER button: the completion handler acts on
// NSAlertFirstButtonReturn (Retry → navigates) and NSAlertSecondButtonReturn (→ the exit path).
- (void)blinkeredDismissOfflinePanelSheetIfAny
{
    NSAlert *panel = _blinkeredOfflinePanelAlert;
    if (!panel) { return; }
    NSWindow *panelWindow = panel.window;
    if (panelWindow && panelWindow.sheetParent) {
        DDLogInfo(@"Blinkered: recovery committed — dismissing the offline panel sheet (attached to %@)",
                  panelWindow.sheetParent);
        [panelWindow.sheetParent endSheet:panelWindow returnCode:NSModalResponseAbort];
        return;
    }
    // Present but unattached: an older presentation path, or already ending. Left alone deliberately —
    // a stale panel a parent can dismiss by hand beats reaching for a modal session this code cannot
    // name. Its appearance in a device log means F5's state gap is real.
    DDLogInfo(@"Blinkered: recovery committed — offline panel is not a sheet, left untouched");
}

/// Restart SEB
///
- (void)requestedRestart
{
    DDLogInfo(@"---------- RESTARTING SEB SESSION -------------");
    _restarting = YES;
    _conditionalInitAfterProcessesChecked = NO;
    _openedURL = NO;

    // If this was a secured exam, we remove it from the list of running exams,
    // otherwise it would be locked next time it is started again
    if (currentExamConfigKey) {
        [self.sebLockedViewController removeLockedExam:currentExamStartURL configKey: currentExamConfigKey];
    }
    
    // Check if the running prohibited processes window is open and close it if yes
    if (_processListViewController) {
        [self closeProcessListWindow];
    }

    // Reset SEB Browser
    [self.browserController resetBrowser];
    
    // Clear private pasteboard
    [self.browserController clearPrivatePasteboard];
    
    if (_batteryController && !_establishingSEBServerConnection) {
        [_batteryController stopMonitoringBattery];
        _batteryController = nil;
    }
    
    // Re-Initialize file logger if logging enabled
    [self initializeLogger];
    [self conditionallyInitSEBWithCallback:self selector:@selector(requestedRestartProcessesChecked)];
}


- (void)requestedRestartProcessesChecked
{
    DDLogDebug(@"%s", __FUNCTION__);
    
    // Check for command key being held down
    NSEventModifierFlags modifierFlags = [NSEvent modifierFlags];
    BOOL cmdKeyDown = (0 != (modifierFlags & NSEventModifierFlagCommand));
    if (cmdKeyDown) {
        if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_enableAppSwitcherCheck"]) {
            // Show alert that keys were hold while starting SEB
            DDLogError(@"Command key is pressed while restarting SEB, show dialog asking to release it.");
            NSAlert *modalAlert = [self newAlert];
            [modalAlert setMessageText:NSLocalizedString(@"Holding Command Key Not Allowed!", @"")];
            [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"Holding the Command key down while restarting %@ is not allowed, release it to continue.", @""), SEBShortAppName]];
            [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
            [modalAlert setAlertStyle:NSAlertStyleCritical];
            void (^cmdKeyHeldProceed)(NSModalResponse) = ^void (NSModalResponse answer) {
                [self removeAlertWindow:modalAlert.window];
                [self requestedRestartProcessesChecked];
            };
            [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))cmdKeyHeldProceed];
            return;
        } else {
            DDLogWarn(@"Command key is pressed, but not forbidden in current settings");
        }
    }
    [self requestedRestartProcessesCmdKeyChecked];
}


- (void)requestedRestartProcessesCmdKeyChecked
{
    // Adjust screen shot blocking
    [self.systemManager adjustScreenCapture];
    
    [self setElevateWindowLevels];

    // Reopen main browser window and load start URL
    DDLogDebug(@"%s re-openMainBrowserWindow", __FUNCTION__);
    
    // Reset session state here, to prevent overriden lock screens for Siri etc. to appear too early
    self.sessionState = nil;

    // [FIX2-G1] THE IN-PROCESS SESSION BOUNDARY. This is the single funnel every -requestedRestart
    // reaches (config-file reconfigure x2, SEB-Server close-with-restart, three proctoring-alert
    // cancellations, and -quitSEBOrSession's quittingSession branch), and it is the only place in
    // the app where one session ends and another begins WITHOUT a new process. Everything the
    // launch path does immediately before -startExamWithFallback: must therefore also happen here.
    // It did not, in two ways:
    //
    //  1. The home-session write latch. A restart begins a session whose first write has not
    //     happened; leaving the latch armed would let the new session's start-URL write take the
    //     replay skip and run with no home_session.json — the degraded state in which the
    //     master-code bridge exit is REFUSED and a parent holding the correct code cannot durably
    //     exit the device. A latch that never resets is the only way this guard can strand someone.
    //  2. -blinkeredClearStaleSessionCredentials had exactly ONE caller, the launch path. So a
    //     home lock restarted in-process as a CLASS session kept the previous home_session.json,
    //     and vice versa — the stale-credential escalation that clear exists to own. Independent
    //     of the guard, and a bug in its own right; it ships here because it is the same oversight.
    //
    //  3. R3-F3 — Fix 2's once-per-outage panel latch. It is process-scoped and nothing else clears
    //     it at a session boundary. Carried into a restarted session it swallows that session's
    //     FIRST offline panel — and removing the panel removes the Retry button, so the
    //     "a human pressing Retry still re-raises" exemption is not violated, it is made
    //     unreachable, which is worse because nothing asserts reachability. This is the third way
    //     the list above warned about, added by the change that needed the warning.
    //
    // Order matters: clear and reset BEFORE -startExamWithFallback: opens the browser, so no window
    // and no interceptor can observe the previous session's state — the same reason the launch path
    // clears before it opens.
    [SEBAbstractWebView blinkeredResetHomeSessionWriteLatch];
    [self blinkeredClearStaleSessionCredentials];
    [self blinkeredResetOfflinePanelOutageLatch];

    [self startExamWithFallback:NO];

    // [FIX2-G1 §5] Re-arm the degraded-lock detector for the restarted session. Scheduling was
    // launch-only, so a home lock reached by restart had none at all.
    [self blinkeredScheduleHomeSessionSanityCheck];

    // Adjust screen locking
    [self adjustScreenLocking:nil];
    
    // ToDo: Opening of additional resources (but not only here, also when starting SEB)
    //    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    //    NSArray *additionalResources = [preferences secureArrayForKey:@"org_safeexambrowser_SEB_additionalResources"];
    //    for (NSDictionary *resource in additionalResources) {
    //        if ([resource valueForKey:@"active"] == [NSNumber numberWithBool:YES]) {
    //            NSString *resourceURL = [resource valueForKey:@"URL"];
    //            NSString *resourceTitle = [resource valueForKey:@"title"];
    //            if ([resource valueForKey:@"autoOpen"] == [NSNumber numberWithBool:YES]) {
    //                [self openResourceWithURL:resourceURL andTitle:resourceTitle];
    //            }
    //        }
    //    }
    _restarting = NO;
}


- (void) conditionallyCloseSEBServerConnectionWithRestart:(BOOL)restart completion:(void (^)(BOOL))completion
{
    if (self.startingExamFromSEBServer || self.establishingSEBServerConnection || self.sebServerConnectionEstablished) {

        NSAlert *modalAlert = [self newAlert];
        [modalAlert setMessageText:[NSString stringWithFormat:NSLocalizedString(@"Disconnecting from SEB Server", @""), SEBShortAppName]];
        [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"If SEB Server doesn't respond for a while, you can forcibly close the connection", @""), SEBShortAppName, SEBShortAppName]];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"Force Close", @"")];
        [modalAlert setAlertStyle:NSAlertStyleCritical];

        void (^forceCloseConnection)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self removeAlertWindow:modalAlert.window];
            DDLogInfo(@"User decided to force close SEB Server connection");
            [self.serverController cancelQuitSessionWithRestart:restart completion:completion];
        };
        
        void (^closeDisconnetingAlertCompletion)(BOOL) = ^void (BOOL restart) {
            DDLogInfo(@"SEB Server connection was closed, closing Disconnecting alert.");
            dispatch_block_cancel(self->cancelableBlock);
            [modalAlert.window orderOut:self];
            [self removeAlertWindow:modalAlert.window];
            completion(restart);
        };

        cancelableBlock = dispatch_block_create(DISPATCH_BLOCK_INHERIT_QOS_CLASS, ^{
            [modalAlert beginSheetModalForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))forceCloseConnection];
        });
        
        dispatch_time_t dispachTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC));
        dispatch_after(dispachTime, dispatch_get_main_queue(), cancelableBlock);

        if (self.startingExamFromSEBServer || self.establishingSEBServerConnection) {
            self.establishingSEBServerConnection = NO;
            self.startingExamFromSEBServer = NO;
            [self.serverController loginToExamAbortedWithCompletion:closeDisconnetingAlertCompletion];
        } else if (self.sebServerConnectionEstablished) {
            self.sebServerConnectionEstablished = NO;
            [self.serverController quitSessionWithRestart:restart completion:closeDisconnetingAlertCompletion];
        }
    } else {
        completion(restart);
    }
}


- (BOOL) quittingSession
{
    BOOL secureClientSession = NO;
    if (self.examSession) {
        secureClientSession = self.secureClientSession;
    }
    BOOL quittingSession = !_startingUp && self.examSession && secureClientSession && !_openedURL;
    DDLogInfo(@"%s: %d", __FUNCTION__, quittingSession);
    return quittingSession;
}

- (BOOL) examSession
{
    return NSUserDefaults.userDefaultsPrivate;
}

- (BOOL) secureClientSession
{
    [NSUserDefaults setUserDefaultsPrivate:NO];
    BOOL secureClientSession = [NSUserDefaults standardUserDefaults].secureSession;
    [NSUserDefaults setUserDefaultsPrivate:YES];
    return secureClientSession;
}


/// Exit SEB
///
- (void)requestedExit:(NSNotification *_Nullable)notification
{
    DDLogInfo(@"%s", __FUNCTION__);
    [self blinkeredStopSessionMarker];   // session ending — let the root updater proceed again
    [self blinkeredSetMenuBarShieldActive:NO];   // give the menu bar back before teardown
    // Stop/Reset proctoring
    [self stopProctoringWithCompletion:^{
        DDLogDebug(@"%s Conditionally closed (optional) proctoring", __FUNCTION__);
        [self conditionallyCloseSEBServerConnectionWithRestart:NO completion:^(BOOL restart) {
            self.establishingSEBServerConnection = NO;
            DDLogDebug(@"%s Conditionally closed (optional) SEB Server connection (restart: %d)", __FUNCTION__, restart);
            [self exitSEB];
        }];
    }];
}

// ── Crash-resilience helpers (mirror of the agent's Swift scrub + marker writer). Log hygiene: strip
// URLs / home paths / emails so a child's name or a token can't reach a log file. Markers: drop a
// small SCRUBBED record to the dir the agent flushes each poll (recorder/sender split — the app never
// has the device token, so it only records; the agent sends).
static NSString *BlinkeredScrub(NSString *s) { return [MyGlobals blinkeredScrub:s]; }

static void BlinkeredWriteCrashMarker(NSString *exceptionType, NSString *method, NSArray<NSString *> *stack, NSString *phase)
{
    NSMutableArray<NSString *> *st = [NSMutableArray array];
    for (NSString *frame in stack) { [st addObject:BlinkeredScrub(frame)]; if (st.count >= 5) break; }
    NSString *appVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"unknown";
    NSOperatingSystemVersion v = [[NSProcessInfo processInfo] operatingSystemVersion];
    NSDictionary *marker = @{
        @"exceptionType": BlinkeredScrub(exceptionType),
        @"method":        BlinkeredScrub(method),
        @"stack":         st,
        @"phase":         BlinkeredScrub(phase),
        @"appVersion":    appVersion,
        @"os":            [NSString stringWithFormat:@"macOS %ld.%ld.%ld", (long)v.majorVersion, (long)v.minorVersion, (long)v.patchVersion],
        @"at":            @([[NSDate date] timeIntervalSince1970]),
        @"attempts":      @0,
    };
    NSURL *appSupport = [[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *dir = [[appSupport URLByAppendingPathComponent:@"Blinkered"] URLByAppendingPathComponent:@"crash-markers"];
    [[NSFileManager defaultManager] createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSURL *file = [dir URLByAppendingPathComponent:[[NSUUID UUID].UUIDString stringByAppendingPathExtension:@"json"]];
    NSData *data = [NSJSONSerialization dataWithJSONObject:marker options:0 error:nil];
    if (data) [data writeToURL:file atomically:YES];
}

// Atomic teardown, M0: SEB is built to fight exactly what the teardown does. Hiding our windows
// activates the next app (NSApplicationDidResignActive / NSWorkspaceDidActivateApplication /
// NSWorkspaceDidUnhideApplication) and restoring the presentation options fires the
// currentSystemPresentationOptions KVO — every one of those funnels into regainActiveStatus:, which
// re-activates SEB, re-raises the main browser window and hides the kid's apps again. Home lockdowns
// always arm that path (elevateWindowLevels is set whenever allowSwitchToApplications is false), so
// the disarm has to happen before anything visual moves.
//
// The gates in regainActiveStatus: / observeValueForKeyPath: are the load-bearing half (they also
// catch notifications already in flight); removing the observers is the belt-and-braces half. Note
// the two notification centers — removeObserver: on the wrong one no-ops silently.
- (void)blinkeredDisarmReassertMachinery
{
    [[NSNotificationCenter defaultCenter] removeObserver:self
                                                    name:NSApplicationDidResignActiveNotification
                                                  object:NSApp];
    NSNotificationCenter *workspaceCenter = [[NSWorkspace sharedWorkspace] notificationCenter];
    [workspaceCenter removeObserver:self
                               name:NSWorkspaceDidActivateApplicationNotification
                             object:nil];
    [workspaceCenter removeObserver:self
                               name:NSWorkspaceDidUnhideApplicationNotification
                             object:nil];
    [self removeKeyPathObservers];   // idempotent — applicationWillTerminateProceed calls it again
    DDLogInfo(@"Blinkered teardown: re-assert machinery disarmed");
}

// Atomic teardown, M2 steps 2–5. One runloop turn, this order: stop enforcement, hide everything,
// restore the presentation options, unhide the kid's apps. Everything after this point in the quit
// (cookie save, terminate, dashboard surfacing, system-settings restore) happens on an already-clean
// desktop, invisibly. The disarm (M0) must have run first or every step here gets fought.
- (void)blinkeredAtomicVisualTeardown
{
    // Never under Assessment Mode. No Blinkered config enables AAC, so the cut buys nothing there,
    // while hiding every window before endAssessmentModeWithCallback: rests on an unprovable claim
    // that ending the assessment session needs no visible window. Same condition
    // applicationShouldTerminate's AAC branch keys on. Guarded here rather than at the call site so
    // no future caller can bypass it — the flag, disarm and watchdogs stay unconditional.
    if (_isAACEnabled && _wasAACEnabled) {
        DDLogInfo(@"Blinkered teardown: Assessment Mode active — skipping the atomic visual cut");
        return;
    }

    // 2. Stop enforcement BEFORE hiding anything: a process watcher still killing prohibited apps
    //    after the desktop is back would fight the kid's own apps while the process lingers.
    [self stopProcessWatcher];
    [self stopWindowWatcher];
    if (_accentPopoverRaiseTimer) {         // the one remaining front-app re-assert timer
        [_accentPopoverRaiseTimer invalidate];
        _accentPopoverRaiseTimer = nil;
        _accentPopoverRaiseDeadline = nil;
    }

    // 3. Hide everything at once — browser windows, native lock/site windows, caps, shields. NSApp.windows
    //    is the whole set the process owns, so nothing survives as a lone window mid-teardown. orderOut:
    //    only unmaps; the later closeAllBrowserWindows still runs its normal teardown on real windows.
    [self blinkeredSetMenuBarShieldActive:NO];
    for (NSWindow *window in [NSApp.windows copy]) {
        [window orderOut:self];
    }

    // 4. Give the menu bar and Dock back in the same turn (they would otherwise return only when the
    //    process dies, popping in after the desktop is already visible).
    @try {
        [NSApp setPresentationOptions:NSApplicationPresentationDefault];
        [[MyGlobals sharedMyGlobals] setPresentationOptions:NSApplicationPresentationDefault];
    }
    @catch (NSException *exception) {
        DDLogError(@"Blinkered teardown: restoring default presentation options failed (%@)", exception.name);
    }

    // 5. Unhide the kid's apps now, not in applicationWillTerminateProceed — otherwise the revealed
    //    desktop is empty and repopulates seconds later (or never, if a watchdog fires first).
    [self blinkeredUnhidePreviouslyVisibleApps];

    DDLogInfo(@"Blinkered teardown: atomic visual cut done — desktop is the kid's again");
}

// The apps that were visible when SEB started and got hidden for the session. Idempotent: unhiding an
// already-visible app is a no-op, so applicationWillTerminateProceed can still call this as a backstop
// for the exits that never reach the atomic cut.
- (void)blinkeredUnhidePreviouslyVisibleApps
{
    runningAppsWhileTerminating = [[NSWorkspace sharedWorkspace] runningApplications];
    for (NSRunningApplication *iterApp in runningAppsWhileTerminating) {
        NSString *appBundleID = [iterApp valueForKey:@"bundleIdentifier"];
        if (appBundleID && [visibleApps indexOfObject:appBundleID] != NSNotFound) {
            [iterApp unhide]; //unhide the originally visible application
        }
    }
}

// Atomic teardown, M2 step 6 — the two deadlines that bound an invisible zombie.
//
// Both fire on a GLOBAL queue, never the main queue: the hangs they exist for ARE main-thread hangs
// (blinkeredSelectDashboardTabInBrowser's synchronous AppleScript, a wedged WebKit networking process
// never calling getAllCookies back), and a main-queue timer would hang alongside them.
//
// There is nothing to cancel — the process is gone before a surviving deadline could fire, and if it
// isn't, firing is the correct outcome. Everything past the kill point (dashboard surfacing, touch-bar
// restore) is knowingly sacrificed: the kid is already at a fully restored desktop.
static const NSTimeInterval kBlinkeredTeardownBackstopSeconds = 15.0;   // whole quit, incl. the cookie save
static const NSTimeInterval kBlinkeredTeardownPostSaveSeconds = 3.0;    // everything after the save

- (void)blinkeredArmTeardownWatchdog:(NSTimeInterval)seconds marker:(NSString *)marker
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        // Distinct marker per deadline so watchdog fires are attributable in telemetry. NSLog as well
        // as DDLog: DDLog is asynchronous and exit(0) is a hard stop, so flush first and keep a copy
        // on a path that does not depend on the logger's queue draining.
        DDLogError(@"%@", marker);
        NSLog(@"%@", marker);
        [DDLog flushLog];
        exit(0);
    });
}

// Test hook for the Stage 5 watchdog acceptance checks — a ONE-SHOT marker file, read and DELETED at
// the top of exitSEB so it can never persist beyond the unlock it was created for. It cannot weaken a
// lockdown: everything it stalls happens AFTER the atomic cut has handed the desktop back, and the
// watchdog it exists to demonstrate is what ends the process.
//   echo hang-save    > ~/Library/Application\ Support/Blinkered/teardown-test   (→ 15 s backstop)
//   echo hang-surface > ~/Library/Application\ Support/Blinkered/teardown-test   (→ 3 s post-save)
static NSString *_blinkeredTeardownTestHook = nil;

static NSString *BlinkeredConsumeTeardownTestHook(void)
{
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *path = [[[dirs firstObject] stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"teardown-test"];
    NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (!contents) return nil;
    NSDate *written = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil][NSFileModificationDate];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];   // one-shot, whatever its age
    // A hook is for the unlock the tester is about to perform. Ignoring a stale file means a planted
    // one cannot surprise an unlock days later.
    if (!written || -written.timeIntervalSinceNow > 600) {
        DDLogError(@"Blinkered teardown: test hook file ignored and deleted — older than 10 minutes");
        return nil;
    }
    NSString *hook = [contents stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    DDLogError(@"Blinkered teardown: TEST HOOK '%@' consumed — this unlock is deliberately wedged", hook);
    return hook.length ? hook : nil;
}

- (void)exitSEB
{
    DDLogInfo(@"%s", __FUNCTION__);
    quittingMyself = YES; //quit SEB without asking for confirmation or password

    // Atomic teardown (M0/M1): set unconditionally, and never as an early return here — the AAC
    // double-entry through terminateSEB is designed, and every caller (page quit, /seb-quit, the
    // offline master-code exit, requestedExit:) must get the disarm. Dedupe of the page's
    // double trigger is a check at the entry points, not here.
    _blinkeredTeardownStarted = YES;

    // Armed first, so it bounds the atomic cut itself as well as the save. This is the ONLY bound on
    // the canonical hang — getAllCookies never calling back — which on an offline master-code exit no
    // agent poll or boundary would ever clean up.
    [self blinkeredArmTeardownWatchdog:kBlinkeredTeardownBackstopSeconds
                                marker:@"BLINKERED teardown watchdog: BACKSTOP fired (15s) — quit wedged before terminate, exiting"];

    [self blinkeredDisarmReassertMachinery];
    [self blinkeredAtomicVisualTeardown];

    // Read after the cut, never before it — the hook's file I/O has no business on the path that has
    // to be instant, and neither wedge it can request happens until later anyway.
    _blinkeredTeardownTestHook = BlinkeredConsumeTeardownTestHook();

    if ([_blinkeredTeardownTestHook isEqualToString:@"hang-save"]) {
        DDLogError(@"Blinkered teardown: TEST HOOK hang-save — skipping the cookie save entirely, the backstop must end this process");
        return;
    }

    if (_browserController && [[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_examSessionClearCookiesOnEnd"]) {
        [self.browserController resetAllCookiesWithCompletionHandler:^{
            DDLogInfo(@"%s All cookies have been reset, continue terminating", __FUNCTION__);
            [self blinkeredArmTeardownWatchdog:kBlinkeredTeardownPostSaveSeconds
                                        marker:@"BLINKERED teardown watchdog: POST-SAVE fired (3s) — cookies safe, quit wedged after the save, exiting"];
            [self blinkeredTerminateAfterCookieSave];
        }];
    } else {
        // Persist WKWebView cookies to a JSON file so they survive the next launch.
        // NSHTTPCookieStorage flushes lazily and may not write before [NSApp terminate:nil],
        // so we write a JSON file atomically ourselves instead.
        WKHTTPCookieStore *cookieStore = self.browserController.wkWebViewConfiguration.websiteDataStore.httpCookieStore;
        [cookieStore getAllCookies:^(NSArray<NSHTTPCookie *> *cookies) {
            NSLog(@"BLINKERED exitSEB: getAllCookies returned %lu cookies", (unsigned long)cookies.count);
            // The save came back, so the state from here on is safe to kill — bound the rest of the
            // quit (write, terminate, dashboard surfacing, system-settings restore) at 3s.
            [self blinkeredArmTeardownWatchdog:kBlinkeredTeardownPostSaveSeconds
                                        marker:@"BLINKERED teardown watchdog: POST-SAVE fired (3s) — cookies safe, quit wedged after the save, exiting"];
            NSMutableArray *cookieArray = [NSMutableArray array];
            for (NSHTTPCookie *cookie in cookies) {
                // Fault-isolation: a single malformed cookie (empty name, odd encoding) must never take
                // down the save — skip it and keep going, and drop a marker so we can see it happened.
                // This is Phase 2's first telemetry source. Never log the cookie name/value/domain.
                @try {
                    NSMutableDictionary *d = [NSMutableDictionary dictionary];
                    d[@"name"]     = cookie.name ?: @"";
                    d[@"value"]    = cookie.value ?: @"";
                    d[@"domain"]   = cookie.domain ?: @"";
                    d[@"path"]     = cookie.path ?: @"/";
                    d[@"secure"]   = @(cookie.isSecure);
                    d[@"httpOnly"] = @(cookie.isHTTPOnly);
                    if (cookie.expiresDate) d[@"expires"] = @(cookie.expiresDate.timeIntervalSince1970);
                    [cookieArray addObject:d];
                } @catch (NSException *ex) {
                    NSLog(@"BLINKERED exitSEB: skipped a malformed cookie (%@)", ex.name);
                    BlinkeredWriteCrashMarker(ex.name ?: @"CookieError", @"exitSEB.saveCookies",
                                              @[@"getAllCookies", @"cookieSerialize"], @"cookie-restore");
                }
            }
            // Blinkered per-child isolation: if this was a kid focus session, save the session's
            // cookies to THIS child's file (so they stay logged in next time) and do NOT pollute the
            // global cookies.json with one kid's logins.
            NSString *focusChild = self.browserController.blinkeredFocusChildId;
            if (focusChild.length > 0) {
                [self.browserController blinkeredSaveCookies:cookies forChild:focusChild];
                NSLog(@"BLINKERED exitSEB: saved %lu cookies to a child list (skipped global cookies.json)", (unsigned long)cookies.count);
                [self blinkeredTerminateAfterCookieSave];
                return;
            }
            NSURL *appSupport = [[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] firstObject];
            NSURL *dir = [appSupport URLByAppendingPathComponent:@"Blinkered"];
            [[NSFileManager defaultManager] createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:nil error:nil];
            NSURL *cookieFile = [dir URLByAppendingPathComponent:@"cookies.json"];
            NSData *data = [NSJSONSerialization dataWithJSONObject:cookieArray options:NSJSONWritingPrettyPrinted error:nil];
            [data writeToURL:cookieFile atomically:YES];
            NSLog(@"BLINKERED exitSEB: wrote %lu cookies to %@", (unsigned long)cookies.count, BlinkeredScrub(cookieFile.path));
            [self blinkeredTerminateAfterCookieSave];
        }];
    }
}

// Single terminate point for every cookie-save completion, so the hang-surface test hook has one
// place to wedge the main thread the way a stuck AppleScript surfacing step does.
- (void)blinkeredTerminateAfterCookieSave
{
    if ([_blinkeredTeardownTestHook isEqualToString:@"hang-surface"]) {
        DDLogError(@"Blinkered teardown: TEST HOOK hang-surface — blocking the main thread after the save, the 3s watchdog must end this process");
        [NSThread sleepForTimeInterval:60.0];
    }
    [NSApp terminate:nil];
}


#pragma mark - Action and Application Delegates for Quitting SEB

// Called when SEB should be terminated
- (NSApplicationTerminateReply) applicationShouldTerminate:(NSApplication *)sender
{
	if (quittingMyself || systemPreferencesOpenedForScreenRecordingPermissions) {
        DDLogDebug(@"%s: quttingMyself = true", __FUNCTION__);
        if (_isAACEnabled && _wasAACEnabled && !_isTerminating) {
            // Don't try to switch AAC off if it didn't switch on yet
            if (@available(macOS 10.15.4, *)) {
                _isTerminating = YES; //prevent trying to switch AAC off twice

                if (self.browserController) {
                    [self.browserController closeAllBrowserWindows];
                }

                [self.assessmentModeManager endAssessmentModeWithCallback:self selector:@selector(terminateSEB) quittingToAssessmentMode:NO];
                return NSTerminateCancel;
            }
        }
		return NSTerminateNow; //SEB wants to quit, ok, so it should happen
	} else { //SEB should be terminated externally(!)
		return NSTerminateCancel; //this we can't allow, sorry...
	}
}


- (void) terminateSEB
{
    DDLogInfo(@"Terminating SEB after ending Assessment Mode");
    [self exitSEB];
}


// Called just before SEB will be terminated
- (void) applicationWillTerminate:(NSNotification *)aNotification
{
    // [R8 D] The typed master code must not outlive the quit on ANY branch. It is normally cleared
    // where the parent-exit marker is written, but that lives inside the server-notify path — the
    // screen-proctoring cache-upload quit reaches neither, so the plaintext could sit in a static
    // until the process died. Short-lived either way; the point is that the guarantee shouldn't
    // depend on which quit branch ran.
    _blinkeredQuitTypedCode = nil;
    DDLogDebug(@"%s", __FUNCTION__);

    // M3: this re-raise exists for legacy alert display on non-Blinkered exits. On a teardown it
    // pulls our already-hidden windows back to the front — the one call that would undo the atomic
    // cut after it ran.
    if (!_blinkeredTeardownStarted) {
        [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    }

    if (self.browserController) {
        [self.browserController closeAllBrowserWindows];
    }
    BOOL success = [self.sebFileManager removeTempDownUploadDirectory];
    DDLogInfo(@"Removing temporary down/upload directory was %@successfull.", success ? @"":@"not ");

    // If this was a secured exam, we remove it from the list of running exams,
    // otherwise it would be locked next time it is started again
    if (currentExamConfigKey) {
        [self.sebLockedViewController removeLockedExam:currentExamStartURL configKey: currentExamConfigKey];
    }
    
    if (enforceMinMacOSVersion) {
        [self applicationWillTerminateProceed];
    } else if (_forceAppFolder) {
        // Show alert that SEB is not placed in Applications folder
        NSString *applicationsDirectoryName = @"Applications";
        NSString *localizedApplicationDirectoryName = [[NSFileManager defaultManager] displayNameAtPath:NSSearchPathForDirectoriesInDomains(NSApplicationDirectory, NSLocalDomainMask, YES).lastObject];
        NSString *localizedAndInternalApplicationDirectoryName;
        if ([localizedApplicationDirectoryName isEqualToString:applicationsDirectoryName]) {
            // System language is English or the Applications folder is named identically in user's current language
            localizedAndInternalApplicationDirectoryName = applicationsDirectoryName;
        } else {
            NSBundle *preferredLanguageBundle = [NSBundle bundleWithPath:[[NSBundle mainBundle] pathForResource:[[NSLocale preferredLanguages] objectAtIndex:0] ofType:@"lproj"]];
            if (preferredLanguageBundle) {
                localizedAndInternalApplicationDirectoryName = [NSString stringWithFormat:@"'%@' ('%@')", localizedApplicationDirectoryName, applicationsDirectoryName];
            } else {
                // User selected language is one which SEB doesn't support
                localizedAndInternalApplicationDirectoryName = [NSString stringWithFormat:@"%@ ('%@')", applicationsDirectoryName, localizedApplicationDirectoryName];
                localizedApplicationDirectoryName = applicationsDirectoryName;
            }
        }
        NSAlert *modalAlert = [self newAlert];
        [modalAlert setMessageText:[NSString stringWithFormat:NSLocalizedString(@"%@ Not in %@ Folder!", @""), SEBShortAppName, localizedApplicationDirectoryName]];
        [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"%@ has to be placed in the %@ folder in order for all features to work correctly. Move the '%@' app to your %@ folder and make sure that you don't have any other versions of %@ installed on your system. %@ will quit now.", @""), SEBShortAppName, localizedApplicationDirectoryName, SEBFullAppNameClassic, localizedAndInternalApplicationDirectoryName, SEBShortAppName, SEBShortAppName]];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
        [modalAlert setAlertStyle:NSAlertStyleCritical];
        void (^terminateSEBAlertOK)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self removeAlertWindow:modalAlert.window];
            [self applicationWillTerminateProceed];
        };
        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))terminateSEBAlertOK];
    } else if (screenCapturePermissionsRequested) {
        screenCapturePermissionsRequested = NO;
        if (@available(macOS 10.15, *)) {
            NSString *accessibilityPermissionsTitleString = @"";
            NSString *accessibilityPermissionsMessageString = @"";
            if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_enableScreenProctoring"]) {
                // Check if also Accessibility permissions need to be granted
                NSDictionary *options = @{(__bridge id)
                                          kAXTrustedCheckOptionPrompt : @NO};
                if (!AXIsProcessTrustedWithOptions((CFDictionaryRef)options)) {
                    accessibilityPermissionsTitleString = accessibilityTitleString;
                    accessibilityPermissionsMessageString = [NSString stringWithFormat:@"\n\n%@", self.accessibilityMessageString];
                }
            }
            if (CGRequestScreenCaptureAccess()) {
                DDLogInfo(@"Screen capture access has been granted");
            } else {
                DDLogError(@"User has to grant screen capture access, display authorization dialog or open System Settings");
                systemPreferencesOpenedForScreenRecordingPermissions = YES;

                NSAlert *modalAlert = [self newAlert];
                [modalAlert setMessageText:[NSString stringWithFormat:@"%@%@", NSLocalizedString(@"Permissions Required for Screen Capture", @""), accessibilityPermissionsTitleString]];
                [modalAlert setInformativeText:[NSString stringWithFormat:@"%@%@", [NSString stringWithFormat:NSLocalizedString(@"For this exam session, screen capturing is required. You need to authorize Screen Recording for %@ in System Settings / Security & Privacy%@. Then restart %@ and your exam.", @""), SEBFullAppNameClassic, @"", SEBShortAppName], accessibilityPermissionsMessageString]];

                [modalAlert addButtonWithTitle:NSLocalizedString(@"Authorize", @"")];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"Quit", @"")];
                [modalAlert setAlertStyle:NSAlertStyleCritical];
                void (^permissionsForProctoringHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                    [self removeAlertWindow:modalAlert.window];
                    switch(answer)
                    {
                        case NSAlertFirstButtonReturn:
                        {
                            DDLogDebug(@"User selected Authorize Screen Recording%@ in System Settings", accessibilityPermissionsTitleString.length == 0 ? @"" : @" and Accessibility");
                            [[NSWorkspace sharedWorkspace] openURL: [NSURL URLWithString:pathToSecurityPrivacyPreferences]];
                            return;
                        }
                        default:
                            DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld. Quitting SEB", (long)answer);
                        case NSAlertSecondButtonReturn:
                        {
                            DDLogDebug(@"No permissions for screen capture: Quitting");
                        }
                    }
                    [self applicationWillTerminateProceed];

                };
                [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))permissionsForProctoringHandler];
                return;
            }
        } else {
            [self applicationWillTerminateProceed];
        }

    } else if (_cmdKeyDown) {
        // Show alert that keys were hold while starting SEB
        NSAlert *modalAlert = [self newAlert];
        [modalAlert setMessageText:NSLocalizedString(@"Holding Command Key Not Allowed!", @"")];
        [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"Holding the Command key down while starting %@ is not allowed. Restart %@ without holding any keys.", @""), SEBShortAppName, SEBShortAppName]];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
        [modalAlert setAlertStyle:NSAlertStyleCritical];
        void (^terminateSEBAlertOK)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self removeAlertWindow:modalAlert.window];
            [self applicationWillTerminateProceed];
        };
        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))terminateSEBAlertOK];
    } else {
        if ([ProcessManager sharedProcessManager].permittedApplications.count > 0) {
            // In case of permitted additional applications, we have to terminate running permitted applications (will be added in that method)
            [self terminateApplications:@[] processes:@[] starting:NO restarting:NO callback:self selector:@selector(applicationWillTerminateProceed)];
        } else {
            [self applicationWillTerminateProceed];
        }
    }
}

#pragma mark - Blinkered: surface the kid's dashboard TAB on exit (validated on-device 22 Jul 2026)

// Bring the kid's EXISTING Blinkered tab to the front on unlock — the correct tab, not just the
// browser. This runs from the FOREGROUND app (which holds the TCC grants and can prompt for them),
// NEVER from the background agent: an agent doing Apple Events/AX churned and got BTM-disabled, which
// silently unprotected the device after a reboot (3.6.145). The agent stays unchanged (it only
// activates the browser). student.html can redirect (welcome/home), so match the DOMAIN / brand, not
// the /student path.
static NSString * const kBlinkeredTabURLMatch   = @"blinkered.com.au";   // Chromium/Safari: match tab URL
static NSString * const kBlinkeredTabTitleMatch = @"Blinkered";          // Firefox (AX): match tab title

// AppleScript to select + reload + raise the Blinkered tab in a Chromium-family browser (Chrome/Edge/
// Brave/Vivaldi/Opera share Chrome's dictionary), addressed by `application id`. No `activate` — the
// agent brings the browser forward. `reload t` handles a tab that errored to the offline page while
// backgrounded (validated: without it you land on Chrome's "check your network cables" page).
- (NSString *)blinkeredChromiumTabScript:(NSString *)bundleId
{
    return [NSString stringWithFormat:
        @"if application id \"%@\" is running then\n"
        "  tell application id \"%@\"\n"
        "    repeat with w in windows\n"
        "      set i to 0\n"
        "      repeat with t in tabs of w\n"
        "        set i to i + 1\n"
        "        if (URL of t) contains \"%@\" then\n"
        "          set active tab index of w to i\n"
        "          set index of w to 1\n"
        "          reload t\n"
        "          return true\n"
        "        end if\n"
        "      end repeat\n"
        "    end repeat\n"
        "  end tell\n"
        "end if\n"
        "return false\n", bundleId, bundleId, kBlinkeredTabURLMatch];
}

// Safari has no per-tab `reload` command; re-setting the tab URL to itself retries even from an error
// page (validated). `current tab` is Safari's active-tab setter.
- (NSString *)blinkeredSafariTabScript
{
    return [NSString stringWithFormat:
        @"if application id \"com.apple.Safari\" is running then\n"
        "  tell application id \"com.apple.Safari\"\n"
        "    repeat with w in windows\n"
        "      repeat with t in tabs of w\n"
        "        if (URL of t) contains \"%@\" then\n"
        "          set current tab of w to t\n"
        "          set index of w to 1\n"
        "          set URL of t to (get URL of t)\n"
        "          return true\n"
        "        end if\n"
        "      end repeat\n"
        "    end repeat\n"
        "  end tell\n"
        "end if\n"
        "return false\n", kBlinkeredTabURLMatch];
}

- (NSString *)blinkeredTabScriptForBundleId:(NSString *)bundleId
{
    static NSSet *chromium;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ chromium = [NSSet setWithArray:@[@"com.google.Chrome",
        @"com.microsoft.edgemac", @"com.brave.Browser", @"com.vivaldi.Vivaldi", @"com.operasoftware.Opera"]]; });
    if ([chromium containsObject:bundleId]) return [self blinkeredChromiumTabScript:bundleId];
    if ([bundleId isEqualToString:@"com.apple.Safari"]) return [self blinkeredSafariTabScript];
    return nil;   // Firefox etc. → Accessibility path
}

// ── Automation (Apple Events) preflight — the teardown block ─────────────────────────────────────
//
// THE BUG THIS CLOSES (Poppy's Mac, 18 Aug 2026, root-confirmed from the device's own log).
// blinkeredRunTabScript: runs NSAppleScript SYNCHRONOUSLY on the main thread, and its only caller is
// on the quit path (applicationWillTerminateProceed). The FIRST time it targets a given browser on a
// given Mac, macOS raises the Automation consent prompt ("Blinkered wants to control Safari") and the
// call BLOCKS until a human answers. At teardown nobody is watching a kid's laptop, so nothing does:
//
//     11:31:00:461  -[SEBController applicationWillTerminateProceed]
//     11:31:03:476  BLINKERED teardown watchdog: POST-SAVE fired (3s) — quit wedged after the save
//
// The watchdog then exit(0)s the process, which CANCELS the prompt without recording a decision — so
// the next unlock prompts again, and the next, indefinitely. Every unlock costs 3 s of frozen quit and
// flashes a dialog that is on screen too briefly to answer. Once consent exists the same call returns
// in 63 ms (same device, next session: "AppleScript found no dashboard tab … trying Accessibility").
//
// WHY IT CAN LIE DORMANT FOR WEEKS. Consent is keyed per (client → TARGET) pair. The lockdown force-
// terminates Chrome at launch (:12009 shortlist notwithstanding, it is a non-com.apple. bundle), so by
// teardown the surviving browser is Safari — and a Chrome grant does not cover Safari.
//
// THE FIX. Ask whether we ALREADY hold consent, with askUserIfNeeded = NO, and skip the script when we
// do not. AEDeterminePermissionToAutomateTarget is the only call that answers that question without
// being able to block on a human: it turns "would prompt" into the return code
// errAEEventWouldRequireUserConsent instead of a modal dialog on a quitting app.
//
// SKIPPING COSTS NOTHING. blinkeredSelectDashboardTabInBrowser falls through to the Accessibility path
// (no extra grant needed — the app already holds Accessibility for kiosk), and failing that to
// applicationWillTerminateProceed's "open the dashboard fresh" branch. The kid still lands on their
// dashboard; only the which-tab refinement is lost, and only on machines that never granted Automation.
//
// DELIBERATELY NEVER PROMPTS. A teardown is the worst possible moment to ask a question: the app is
// mid-quit, both watchdogs are armed, and the person who could answer is usually not in the room. If
// this grant is ever worth having, it must be requested from a LIVE session, never from a quit.
- (BOOL)blinkeredAutomationPermittedFor:(NSString *)bundleId
{
    NSAppleEventDescriptor *target = [NSAppleEventDescriptor descriptorWithBundleIdentifier:bundleId];
    if (!target) return NO;
    // typeWildCard/typeWildCard = "any event to this target" — the documented way to ask the general
    // question rather than probing with a real event (which is what would block).
    OSStatus status = AEDeterminePermissionToAutomateTarget(target.aeDesc, typeWildCard, typeWildCard, NO);
    switch (status) {
        case noErr:
            return YES;
        case errAEEventWouldRequireUserConsent:      // -1744: never asked. Asking HERE is the bug.
            DDLogInfo(@"Blinkered: Automation consent for %@ not yet granted — skipping the tab-select AppleScript (it would block the quit)", bundleId);
            return NO;
        case errAEEventNotPermitted:                 // -1743: asked and denied, or blocked by policy
            DDLogInfo(@"Blinkered: Automation for %@ denied — using the Accessibility path", bundleId);
            return NO;
        default:                                     // procNotFound etc. — fail closed, never prompt
            DDLogInfo(@"Blinkered: Automation preflight for %@ returned %d — skipping the AppleScript", bundleId, (int)status);
            return NO;
    }
}

// Run the tab-select AppleScript in-process. Under hardened runtime this needs the
// com.apple.security.automation.apple-events entitlement + an Automation grant for the target browser.
// Callers MUST gate this on blinkeredAutomationPermittedFor: — reaching here without consent is what
// wedged the quit for 3 s. The error branch below now only catches genuine script failures (a denial
// can no longer get this far). Returns YES if a matching tab was found + selected.
- (BOOL)blinkeredRunTabScript:(NSString *)source
{
    NSAppleScript *script = [[NSAppleScript alloc] initWithSource:source];
    if (!script) return NO;
    NSDictionary *err = nil;
    NSAppleEventDescriptor *result = [script executeAndReturnError:&err];
    if (err) {
        DDLogWarn(@"Blinkered: tab-select AppleScript unavailable (err %@)", err[NSAppleScriptErrorNumber]);
        return NO;
    }
    return result.booleanValue;
}

// Firefox exposes no scripting API. Its tabs are AXRadioButton with the page title in AXTitle, so we
// find the tab whose title contains "Blinkered" and AXPress it (validated on-device). The app already
// holds Accessibility (for kiosk), so no extra grant is needed. Returns a +1 retained ref or NULL.
static NSString *blinkeredAXStr(AXUIElementRef el, CFStringRef attr)
{
    CFTypeRef v = NULL;
    if (AXUIElementCopyAttributeValue(el, attr, &v) == kAXErrorSuccess && v) {
        if (CFGetTypeID(v) == CFStringGetTypeID()) return (__bridge_transfer NSString *)v;  // ARC takes the +1
        CFRelease(v);
    }
    return nil;
}
static AXUIElementRef blinkeredAXFindTab(AXUIElementRef el, int depth)
{
    if (depth > 40) return NULL;
    NSString *role = blinkeredAXStr(el, kAXRoleAttribute);
    if ([role isEqualToString:@"AXRadioButton"]) {
        NSString *title = blinkeredAXStr(el, kAXTitleAttribute);
        if (title && [title rangeOfString:kBlinkeredTabTitleMatch options:NSCaseInsensitiveSearch].location != NSNotFound) {
            CFRetain(el);
            return el;
        }
    }
    CFTypeRef kidsRef = NULL;
    AXUIElementRef found = NULL;
    if (AXUIElementCopyAttributeValue(el, kAXChildrenAttribute, &kidsRef) == kAXErrorSuccess && kidsRef) {
        for (id k in (__bridge NSArray *)kidsRef) {
            found = blinkeredAXFindTab((__bridge AXUIElementRef)k, depth + 1);
            if (found) break;
        }
        CFRelease(kidsRef);
    }
    return found;
}
- (BOOL)blinkeredAXSelectTabForPid:(pid_t)pid
{
    if (!AXIsProcessTrusted()) { DDLogWarn(@"Blinkered: Accessibility not granted — can't select Firefox tab"); return NO; }
    AXUIElementRef app = AXUIElementCreateApplication(pid);
    // The SECOND stall source on this path. Every AXUIElementCopyAttributeValue below is a synchronous
    // round trip into ANOTHER process, and blinkeredAXFindTab recurses to depth 40 across every window
    // and tab. The system default timeout is 6 s PER MESSAGE, so a browser that is itself busy (or
    // mid-quit, which is exactly when we run) can hold the teardown well past both watchdogs. Setting
    // this on the application element applies it to every element in that app. 1 s is far longer than a
    // healthy a11y round trip and far shorter than the 3 s post-save deadline.
    AXUIElementSetMessagingTimeout(app, 1.0);
    AXUIElementSetAttributeValue(app, CFSTR("AXEnhancedUserInterface"), kCFBooleanTrue);  // wake Firefox's lazy a11y tree
    CFTypeRef windowsRef = NULL;
    BOOL selected = NO;
    if (AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, &windowsRef) == kAXErrorSuccess && windowsRef) {
        for (id w in (__bridge NSArray *)windowsRef) {
            AXUIElementRef tab = blinkeredAXFindTab((__bridge AXUIElementRef)w, 0);
            if (tab) {
                AXUIElementPerformAction(tab, kAXPressAction);
                AXUIElementPerformAction((__bridge AXUIElementRef)w, kAXRaiseAction);
                CFRelease(tab);
                selected = YES;
                break;
            }
        }
        CFRelease(windowsRef);
    }
    CFRelease(app);
    return selected;
}

// Entry point: select the kid's Blinkered tab in the given running browser. Best-effort; returns NO if
// not possible (unsupported browser / TCC not granted) so the caller keeps today's activate-only path.
- (BOOL)blinkeredSelectDashboardTabInBrowser:(NSString *)bundleId pid:(pid_t)pid
{
    NSString *script = [self blinkeredTabScriptForBundleId:bundleId];
    // The preflight is what keeps a quit from blocking on a consent dialog — see the long note above
    // blinkeredAutomationPermittedFor:. Order matters: never build an event for a target we may not
    // script, and never let the && short-circuit be "optimised" into running the script first.
    if (script && [self blinkeredAutomationPermittedFor:bundleId]) {
        if ([self blinkeredRunTabScript:script]) {
            DDLogInfo(@"Blinkered: selected dashboard tab via AppleScript (%@)", bundleId);
            return YES;
        }
        DDLogInfo(@"Blinkered: AppleScript found no dashboard tab in %@ — trying Accessibility", bundleId);
    }
    if ([self blinkeredAXSelectTabForPid:pid]) {
        DDLogInfo(@"Blinkered: selected dashboard tab via Accessibility (%@)", bundleId);
        return YES;
    }
    return NO;
}

- (void) applicationWillTerminateProceed
{
    DDLogDebug(@"%s", __FUNCTION__);

    // Blinkered: belt-and-braces — exits that bypass requestedExit: must still return the menu bar.
    [self blinkeredSetMenuBarShieldActive:NO];

    // Return the student to the Blinkered web app after exiting — but NOT when the web app is
    // already handling the return (a focus/class session's launching tab, or a lockdown's
    // openDashboard). Opening here too spawns a duplicate browser tab on exit.
    //
    // Open /d with the device token from agent.json (same pattern as
    // blinkeredDoBareLaunchRedirect). Without ?token= the kid lands on whatever
    // device's token happens to be in the default browser's localStorage —
    // often a stale one from earlier pairing tests, so a kid Mac assigned to
    // Maddie can land on /d showing Reggie. Passing the token here forces /d
    // to consume it into localStorage on load, so the kid sees the correct
    // persona for THIS device every time.
    // Return the kid to their dashboard on exit WITHOUT opening a duplicate tab. Key browser
    // difference: a bare openURL to the dashboard REUSES an existing tab in Safari but opens a NEW
    // tab in Chrome (reported on a Chrome-default Mac). So ALWAYS prefer SURFACING a running browser
    // (activate it — no navigation, no new tab, Chrome-safe), and openURL fresh only when no browser
    // is running at all (nothing to duplicate). Previously a non-web-return exit — e.g. an agent lock
    // whose web-return bridge didn't fire — took the bare-openURL path and duplicated the tab on
    // Chrome; this unifies every exit on the surfacing path already used for focus/web-return sessions
    // (and matches the _blinkeredSkipTerminateReturn flag's intent: never open a duplicate tab).
    {
        // An openFile session (agent-launched lock / focus / class join) ends with the kid's
        // EXISTING student-dashboard tab still open in their browser — it refreshes itself the
        // moment it becomes visible again (student.html's visibilitychange handler), so we must
        // NOT open a new tab (that's the duplicate-tab bug the skip flag exists to prevent). But
        // macOS hands focus to whatever app is next in the window stack when we quit — Terminal,
        // Finder, anything — leaving that refreshed dashboard buried. So surface the browser,
        // opening nothing; only if the kid closed their browser entirely during the session do we
        // open the dashboard fresh (no duplicate possible).
        //
        // 3.6.115: the surfacing MUST go through LaunchServices (openApplicationAtURL:), the same
        // mechanism as openURL — 3.6.114 used NSRunningApplication -activateWithOptions:, which
        // modern macOS's cooperative-activation rules silently ignore coming from a terminating
        // app, so Terminal kept winning the post-quit focus. LS completes the activation
        // independently of our exiting process.
        //
        // The dashboard tab lives in whichever browser the kid actually USES — normally the
        // default browser, but a family can use Chrome while Safari is the system default; an
        // idle default browser must not steal the surfacing from the one holding the tab. So:
        // default browser first IF RUNNING, else any running browser from the shortlist.
        NSURL *probe = [NSURL URLWithString:@"https://blinkered.com.au"];
        NSURL *defaultBrowserURL = [[NSWorkspace sharedWorkspace] URLForApplicationToOpenURL:probe];
        NSString *defaultBrowserId = defaultBrowserURL ? [NSBundle bundleWithURL:defaultBrowserURL].bundleIdentifier : nil;
        NSMutableArray<NSString *> *candidates = [NSMutableArray array];
        if (defaultBrowserId.length) [candidates addObject:defaultBrowserId];
        [candidates addObjectsFromArray:@[@"com.google.Chrome", @"com.apple.Safari",
                                          @"com.microsoft.edgemac", @"org.mozilla.firefox",
                                          @"company.thebrowser.Browser", @"com.brave.Browser"]];
        NSRunningApplication *target = nil;
        for (NSString *bid in candidates) {
            target = [NSRunningApplication runningApplicationsWithBundleIdentifier:bid].firstObject;
            if (target) break;
        }
        // Blinkered: ensure the kid lands on their dashboard on exit. If a browser is running AND it has
        // an EXISTING Blinkered tab, SELECT it (correct tab, no new tab — validated on-device for
        // Chrome/Safari via AppleScript+URL and Firefox via Accessibility+title). Otherwise — no browser
        // running, OR a browser with no dashboard tab — fall through to the else, which OPENS the
        // dashboard fresh so the kid ALWAYS ends up on it (no duplicate risk: we only open fresh when no
        // dashboard tab was found). Done in the foreground app (holds the TCC grants), not the agent.
        if (target && [self blinkeredSelectDashboardTabInBrowser:target.bundleIdentifier pid:target.processIdentifier]) {
            // Bring the running browser forward by ACTIVATING it directly — NOT via
            // openApplicationAtURL / LaunchServices "open". That path sends a reopen event, and Chrome
            // answers a reopen by popping a NEW tab/window (Safari doesn't) — the duplicate-tab-on-exit
            // reported on a Chrome-default Mac, confirmed in the log ("surfacing … via LaunchServices"
            // fired yet a tab still appeared). activateWithOptions just raises the app's existing
            // windows (the dashboard tab) — no reopen, no new tab. Retry briefly because activation
            // from a terminating process can be dropped once (the reason the LS path was used before);
            // a couple of nudges on the main runloop before we exit make it stick without a reopen.
            DDLogInfo(@"Blinkered: session teardown — activating %@ (raising the student dashboard tab, no reopen)", target.bundleIdentifier);
            for (int i = 0; i < 3; i++) {
                [target activateWithOptions:NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps];
                [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.12]];
            }
        } else {
            // No dashboard tab to surface (no browser running, or a running browser with none) → open
            // it fresh so the kid always lands on their dashboard. openURL opens in the default browser
            // and REUSES an existing matching tab on Safari / opens one on Chrome — fine here because we
            // only reach this when no dashboard tab existed to begin with, so there is nothing to duplicate.
            DDLogInfo(@"Blinkered: session teardown — no dashboard tab to surface, opening the student dashboard fresh");
            [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[self blinkeredStudentDashboardURLString]]];
        }
    }

//    [self killScreenCaptureAgent];
    BOOL success = [self.systemManager restoreScreenCapture];
    DDLogDebug(@"Success of restoring SC: %hhd", success);
    
    [self stopWindowWatcher];
    [self stopProcessWatcher];
    DDLogDebug(@"Returned after stopProcessWatcher");

    [self removeKeyPathObservers];
    DDLogDebug(@"Returned after removeKeyPathObservers");

    if (keyboardEventReturnKey != NULL) {
        DDLogDebug(@"%s CFRelease(keyboardEventReturnKey)", __FUNCTION__);
        CFRelease(keyboardEventReturnKey);
    }
    
    BOOL touchBarRestoreSuccess;
    if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_enableMacOSAAC"] == NO) {
        touchBarRestoreSuccess = [_systemManager restoreSystemSettings];
        DDLogDebug(@"Restored system settings. Restoring TouchBar settings (if available) %@", touchBarRestoreSuccess ? @"was successfull" : @"failed");
        [self killTouchBarAgent];
    }
    
    // Restart terminated apps
    DDLogInfo(@"These processes were terminated by SEB during this session: %@", _terminatedProcessesExecutableURLs);
    
    for (NSURL *executableURL in _terminatedProcessesExecutableURLs) {
        
//        NSArray *taskArguments = [NSArray arrayWithObjects:@"", nil];
        
        if ([executableURL.pathExtension isEqualToString:@"app"] &&
            ![executableURL.path.lastPathComponent isEqualToString:PasswordsMenuBarExtraApp] &&
            ![executableURL.path.lastPathComponent isEqualToString:VoiceOverApp]) {
            NSError *error;
            DDLogInfo(@"Trying to restart terminated process with bundle URL %@", executableURL.path);
            [[NSWorkspace sharedWorkspace] launchApplicationAtURL:executableURL options:NSWorkspaceLaunchDefault configuration:@{} error:&error];
            if (error) {
                DDLogError(@"Error %@", error);
            }
//        } else {
//            // Allocate and initialize a new NSTask
//            NSTask *task = [NSTask new];
//            
//            // Tell the NSTask what the path is to the binary it should launch
//            //        NSString *path = [executableURL.path stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
//            [task setLaunchPath:executableURL.path];
//            
//            [task setArguments:taskArguments];
//            
//            // Launch the process asynchronously
//            @try {
//                DDLogInfo(@"Trying to restart terminated process %@", executableURL.path);
//                [task launch];
//            }
//            @catch (NSException* error) {
//                DDLogError(@"Error %@.  Make sure you have a valid path and arguments.", error);
//            }
        }
    }
    
    // M2 step 5 moved this into the atomic cut, so the revealed desktop is already populated. Kept
    // here as a backstop for exits that never ran the cut; idempotent either way.
    [self blinkeredUnhidePreviouslyVisibleApps];
    [self clearPasteboardCopyingBrowserExamKey];
    
	// Clear the current Browser Exam Key
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    [preferences setSecureObject:[NSData data] forKey:@"org_safeexambrowser_currentData"];

	// Clear the browser cache in ~/Library/Caches/org.safeexambrowser.SEB.Safe-Exam-Browser/
	NSURLCache *cache = [NSURLCache sharedURLCache];
	[cache removeAllCachedResponses];
    
	// Allow display and system to sleep again
	//IOReturn success = IOPMAssertionRelease(assertionID1);
	IOPMAssertionRelease(assertionID1);
	/*// Allow system to sleep again
	success = IOPMAssertionRelease(assertionID2);*/
    
    // Display alert in case TouchBar mode AppControl was active
    // before SEB was started as this mode cannot be automatically restored
    // and open System Preferences / Keyboard to allow user to restore
    // TouchBar mode manually
    if (_touchBarDetected && !touchBarRestoreSuccess && _blinkeredTeardownStarted) {
        // A teardown is unattended by definition: this modal would raise a Blinkered window onto the
        // already-clean desktop AND block termination until the 3s watchdog killed the process — the
        // atomic cut broken, and the dashboard surfacing lost, for an alert nobody is there to read.
        // Skip straight to the alert's continuation (its handler only logs and, on OK, opens System
        // Settings) and leave the marker so a Touch Bar Mac that needs the manual fix is still visible
        // in the log.
        DDLogWarn(@"Blinkered teardown: Touch Bar mode 'App Controls' could not be restored — alert suppressed during teardown");
        DDLogInfo(@"---------- EXITING SEB - ENDING SESSION -------------");
    } else if (_touchBarDetected && !touchBarRestoreSuccess) {
        [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
        NSAlert *modalAlert = [self newAlert];
        [modalAlert setMessageText:NSLocalizedString(@"Cannot Restore Touch Bar Mode",nil)];
        [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"Before running %@, you had the Touch Bar mode 'App Controls' set. %@ cannot restore this setting automatically. You either have to restart your Mac or change the setting manually in System Settings / Keyboard / 'Touch Bar shows'. %@ will open this System Settings tab for you.", @""), SEBShortAppName, SEBShortAppName, SEBShortAppName]];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
        [modalAlert setAlertStyle:NSAlertStyleWarning];
        DDLogInfo(@"Cannot Restore Touch Bar Mode 'App Controls'");
        void (^cannotRestoreTouchBarAlertOK)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self removeAlertWindow:modalAlert.window];
            switch(answer)
            {
                case NSAlertFirstButtonReturn:
                    [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:pathToKeyboardPreferences isDirectory:NO]];
                    DDLogInfo(@"User selected to open System Settings / Keyboard / 'Touch Bar shows'");
                    break;
                default:
                    DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld.", (long)answer);
                case NSAlertSecondButtonReturn:
                    DDLogInfo(@"Exiting SEB without opening System Settings / Keyboard / 'Touch Bar shows'");
            }
            DDLogInfo(@"---------- EXITING SEB - ENDING SESSION -------------");
            return;
        };
        [self runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))cannotRestoreTouchBarAlertOK];
    } else {
        DDLogInfo(@"---------- EXITING SEB - ENDING SESSION -------------");
    }
}


// Called when currentPresentationOptions change
// Called when "isActive" propery of [NSRunningApplication currentApplication] changes

- (void) observeValueForKeyPath:(NSString *)keyPath
					  ofObject:id
                        change:(NSDictionary *)change
                       context:(void *)context
{
    DDLogVerbose(@"Value for key path %@ changed: %@", keyPath, change);

    // Atomic teardown (M0): the teardown restores the menu bar and Dock itself, which fires this
    // handler — without the gate it reads the restore as a kid escaping and switches straight back
    // to SEB. Gated here as well as at the observer removal because a change already queued must
    // find the door shut.
    if (_blinkeredTeardownStarted && [keyPath isEqualToString:@"currentSystemPresentationOptions"]) {
        DDLogDebug(@"%s: teardown started, ignoring currentSystemPresentationOptions change", __FUNCTION__);
        return;
    }

    // If the startKioskMode method changed presentation options, then we don't do nothing here
    if (_isAACEnabled == NO && _wasAACEnabled == NO && [keyPath isEqualToString:@"currentSystemPresentationOptions"]) {
        if ([[MyGlobals sharedMyGlobals] startKioskChangedPresentationOptions]) {
            [[MyGlobals sharedMyGlobals] setStartKioskChangedPresentationOptions:NO];
            return;
        }
        // Current Presentation Options changed, so make SEB active and reset them
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        BOOL allowSwitchToThirdPartyApps = ![preferences secureBoolForKey:@"org_safeexambrowser_elevateWindowLevels"];
        if (!allowSwitchToThirdPartyApps && !self.settingsOpen && !launchedApplication && !fontRegistryUIAgentRunning) {
            // If third party Apps are not allowed, we switch back to SEB
            DDLogInfo(@"Switched back to SEB after currentSystemPresentationOptions changed!");
            [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
            
            [self regainActiveStatus:nil];
        }
    } else if (_isAACEnabled == NO && _wasAACEnabled == NO && [keyPath isEqualToString:@"isActive"]) {
        DDLogWarn(@"isActive property of SEB changed!");
        [self regainActiveStatus:nil];
    } else if ([keyPath isEqualToString:@"runningApplications"]) {
        NSArray *startedProcesses = [change objectForKey:@"new"];
        if (startedProcesses.count > 0) {
            NSArray *prohibitedApplications = [ProcessManager sharedProcessManager].prohibitedApplications;
            
            for (NSRunningApplication *startedApplication in startedProcesses) {
                
                NSString *bundleID = startedApplication.bundleIdentifier;
                if (bundleID && ([bundleID isEqualToString:WebKitNetworkingProcessBundleID] ||
                                 [bundleID isEqualToString:UniversalControlBundleID])) {
                    DDLogVerbose(@"Started application with bundle ID: %@", bundleID);
                } else {
                    DDLogDebug(@"Started application with bundle ID: %@", bundleID);
                }
                
                // Check for running Open and Save Panel Service
                if (!allowOpenAndSavePanel && _isAACEnabled && !self.settingsOpen && bundleID &&
                    [bundleID isEqualToString:openAndSavePanelServiceBundleID]) {
                    [self killApplication:startedApplication];
                }
                
                // Check for Share Sheet UI
                if (!allowShareSheet && _isAACEnabled && !self.settingsOpen && bundleID &&
                    [bundleID isEqualToString:shareSheetBundleID]) {
                    [self killApplication:startedApplication];
                }
                
                // Check if VoiceOver is disabled
                if (voiceOverDisabled &&
                    [bundleID isEqualToString:VoiceOverBundleID]) {
                    DDLogVerbose(@"VoiceOver is disabled in settings, terminating its process.");
                    [self killApplication:startedApplication];
                }
                
                // While in AAC, check if Dictation was started and it is disabled
                if ((_isAACEnabled ||
                    !allowDictation ) &&
                    [bundleID isEqualToString:DictationProcessBundleID]) {
                    DDLogDebug(@"Dictation is disabled in settings or running in AAC, terminating its process.");
                    [self killApplication:startedApplication];
                }
                
                NSPredicate *processFilter = [NSPredicate predicateWithFormat:@"%@ LIKE self", bundleID];
                
                NSArray *matchingProhibitedApplications = [prohibitedApplications filteredArrayUsingPredicate:processFilter];
                if (matchingProhibitedApplications.count != 0) {
                    if ([bundleID isEqualToString:WebKitNetworkingProcessBundleID]) {
                        pid_t processPID = startedApplication.processIdentifier;
                        typedef pid_t (*pidResolver)(pid_t pid);
                        pidResolver resolver = dlsym(RTLD_NEXT, "responsibility_get_pid_responsible_for_pid");
                        pid_t trueParentPid = resolver(processPID);
                        DDLogVerbose(@"PID: %d - Bundle ID: %@ - True Parent PID: %d", processPID, bundleID, trueParentPid);
                        if (trueParentPid == sebPID) {
                            DDLogDebug(@"Not terminating instance of WebKit networking process started by SEB");
                            return;
                        }
                    }
                    [self killApplication:startedApplication];
                }
            }
        } else {
            NSArray *terminatedProcesses = [change objectForKey:@"old"];
            if (terminatedProcesses.count > 0 && _processListViewController != nil) {
                [_processListViewController didTerminateRunningApplications:terminatedProcesses];
            }
        }
    }
}


- (void)closeProcessListWindow
{
    _runningProcessesListWindowController.window.delegate = nil;
    [_runningProcessesListWindowController close];
    _processListViewController = nil;
}

- (void)closeProcessListWindowWithCallback:(id)callback selector:(SEL)selector
{
    DDLogDebug(@"%s callback: %@ selector: %@", __FUNCTION__, callback, NSStringFromSelector(selector));
    BOOL starting = self.processListViewController.starting;
    BOOL restarting = self.processListViewController.restarting;
    [self closeProcessListWindow];
    // Continue to initializing SEB and then starting the exam session
    [self conditionallyContinueAfterTerminatingAppsWithCallback:callback restarting:restarting selector:selector starting:starting];
}


- (NSURL *) getTempDownUploadDirectory
{
    return [self.sebFileManager getTempDownUploadDirectoryWithConfigKey:self.configKey];
}

- (BOOL) removeTempDownUploadDirectory
{
    return [self.sebFileManager removeTempDownUploadDirectory];
}


@end

//
//  BrowserWindow.m
//  Safe Exam Browser
//
//  Created by Daniel R. Schneider on 06.12.10.
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

#import "SEBBrowserWindow.h"
#import "SEBConfigFileManager.h"
#import "SEBBrowserWindowDocument.h"
#import "NSWindow+SEBWindow.h"
#import "SEBURLFilter.h"
#import "NSURL+KKDomain.h"
#import "HUDPanel.h"
#import "NSScreen+SEBScreen.h"

#include <CoreServices/CoreServices.h>

@implementation SEBBrowserWindow
{
    // Launch cleanup #4/#5: black overlay covering the content until the first
    // page painted. An overlay, NOT contentView.hidden — WebKit suppresses JS
    // window.open from a hidden web view, which silently broke the home tab
    // bar's auto-open of the first site window.
    BOOL _blinkeredContentHeld;
    NSView *_blinkeredHoldOverlay;
    // §5: a SEPARATE standing backdrop for "revealed, but there is nothing to reveal". Distinct
    // from the hold overlay above and from _blinkeredContentHeld, which stays NO while it is up —
    // re-entering that flag would suppress blinkeredPaintLockActive and with it the entire
    // wake-edge and paint path (SEBController.m:2756-2766, TODO(recovery-flip)).
    NSView *_blinkeredEmptyContentBackdrop;
    BOOL _blinkeredContentCommitted;
}

@synthesize webView;


- (void)addConstraintsToWebView:(NSView*) nativeWebView
{
    nativeWebView.translatesAutoresizingMaskIntoConstraints = NO;
    [nativeWebView.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor].active = YES;
    [nativeWebView.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor].active = YES;
    [nativeWebView.topAnchor constraintEqualToAnchor:self.contentView.topAnchor].active = YES;
    [nativeWebView.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor].active = YES;
}


- (NSArray *)accessibilityChildren {
    NSArray *subViews = self.contentView.superview.subviews;
    DDLogVerbose(@"Browser window contentView superview subviews: %@", subViews);
    
    return @[self.contentView.superview, self.contentView, self.accessibilityDock];
}


-(BOOL)canBecomeKeyWindow {
    return YES;
}

-(BOOL)canBecomeMainWindow {
    return YES;
}


- (NSTimeInterval)animationResizeTime:(NSRect)newFrame
{
    return 0.1;
}


// Overriding setTitle method to adjust position of progress indicator
- (void)setTitle:(NSString *)title
{
    [super setTitle:title];
    if (!_isFullScreen) {
        [self adjustPositionOfViewInTitleBar:_progressIndicatorHolder atRightOffsetToTitle:10 verticalOffset:0];
    }
}


// Closing of SEB Browser Window //
- (BOOL)windowShouldClose:(id)sender
{
    DDLogDebug(@"SEBBrowserWindow %@ windowShouldClose: %@", self, sender);
    if (self == self.browserController.mainBrowserWindow) {
        // Post a notification that SEB/Session should conditionally quit
        [[NSNotificationCenter defaultCenter]
         postNotificationName:@"requestQuitNotification" object:self];

        return NO; //but don't close the window (that will happen anyways in case quitting is confirmed)
    }
    // Additional browser window: the red close button (and ⌘W) should only HIDE the window,
    // not destroy it, so the student can reopen the exact same page — with login, scroll
    // position and form input intact — from the "Open webpages" menu on the Blinkered dock
    // icon. The dock entry survives because the window is never closed/removed here.
    // Programmatic closes (teacher Clear, session reset, JS window.close) go through
    // closeWebView:/[document close] instead and still destroy the window as before.
    // Blinkered split screen: this is the ONLY path the child's own close gesture takes, and
    // it HIDES rather than closes — so windowWillClose: never fires here. A role-clear hung
    // only on windowWillClose: would miss the commonest way a split ends, leaving the survivor
    // half-width forever (nothing on Mac re-frames a site window outside windowDidMove:/
    // windowDidResize:). Clear BEFORE the orderOut: below — re-framing a hidden window is a
    // no-op, so the order here is load-bearing, not stylistic. See SPLIT_SCREEN_PLAN.md R9.
    [self.browserController blinkeredClearSplitRolesDyingWindow:self];
    DDLogDebug(@"SEBBrowserWindow %@ hiding instead of closing so it stays reopenable from the dock", self);
    [self orderOut:sender];
    return NO;
}


- (BOOL) isTemporaryWindowWhileStartingUp
{
    return self.webView.creatingWebView == self.webView;
}


- (SEBBrowserWindowController *)browserWindowController
{
    return (SEBBrowserWindowController *)self.windowController;
}


// Setup browser window and webView delegates
- (void) awakeFromNib
{
    // Appear/close in place — the default zoom/fade animation is visible during
    // the locked-session launch (the window shows before content paints).
    self.animationBehavior = NSWindowAnimationBehaviorNone;
    // No toolbar on full screen window
    if (!_isFullScreen) {
        // Display or don't display toolbar
        [self conditionallyDisplayToolbar];
    }
    _javaScriptFunctions = self.browserController.pageJavaScript;
    self.contentView.superview.accessibilityLabel = NSLocalizedString(@"Browser Window", @"");
    self.contentView.accessibilityLabel = NSLocalizedString(@"Web Content", @"");
}

- (void)performFindPanelAction:(id)sender
{
    long tag = ((NSMenuItem *)sender).tag;
    switch (tag) {
        case NSFindPanelActionShowFindPanel:
            [self searchText];
            break;
            
        case NSFindPanelActionNext:
            [self searchTextNext];
            break;
            
        case NSFindPanelActionPrevious:
            [self searchTextPrevious];
            break;
            
        default:
            break;
    }
}

- (void) searchText
{
    if (!_isFullScreen) {
        [self displayToolbar];
        [self.browserWindowController searchTextMatchFound:NO];
        [self makeFirstResponder:self.browserWindowController.textSearchField];
    }
}

- (void) searchTextNext
{
    if (!_isFullScreen) {
        [self.browserWindowController searchTextNext];
    }
}

- (void) searchTextPrevious
{
    if (!_isFullScreen) {
        [self.browserWindowController searchTextPrevious];
    }
}



- (void) conditionallyDisplayToolbar
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if (![preferences secureBoolForKey:@"org_safeexambrowser_SEB_enableBrowserWindowToolbar"] || ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_hideBrowserWindowToolbar"] || _toolbarWasHidden))
    {
        _toolbarWasHidden = NO;
        [self.toolbar setVisible:NO];
    } else {
        [self.toolbar setVisible:YES];
    }
}

- (void) displayToolbar
{
    if (!_isFullScreen && !self.toolbar.isVisible) {
        _toolbarWasHidden = !self.toolbar.isVisible;
        [self.toolbar setVisible:YES];
    }
}


- (void) setCalculatedFrame
{
    [self setCalculatedFrameOnScreen:self.screen mainBrowserWindow:NO temporaryWindow:NO];
}

- (void) setCalculatedFrameOnScreen:(NSScreen *)screen
{
    [self setCalculatedFrameOnScreen:self.screen mainBrowserWindow:NO temporaryWindow:NO];
}

- (void) setCalculatedFrameOnScreen:(NSScreen *)screen mainBrowserWindow:(BOOL)mainBrowserWindow temporaryWindow:(BOOL)temporaryWindow
{
    if (mainBrowserWindow || temporaryWindow) {
        screen = _browserController.mainScreen;
    }
    // NSWindow.screen is NIL for an ordered-out window, and -setCalculatedFrame passes
    // self.screen — so re-framing a HIDDEN window silently did nothing. That is exactly the
    // path the split's role-clear depends on (clear the role, then re-frame), and it is why
    // adjustMainBrowserWindow guards on isVisible before calling here. Fall back to the main
    // screen: the same fallback main/temporary windows already get one line above.
    //
    // ONLY for a window that holds a split role. A blanket fallback would re-frame every hidden
    // keep-alive window on paths that have nothing to do with split screen (moveAllBrowserWindowsToScreen:
    // reaches them, since a hidden window's screen is nil and therefore never equal to the target)
    // — a behaviour change for every device, to fix a case only the split can produce.
    if (!screen && self.blinkeredSplitRole != SEBBlinkeredSplitRoleNone) {
        screen = _browserController.mainScreen;
    }
    if (screen) {
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        
        // Get frame of the usable screen (considering if menu bar or SEB dock is enabled)
        NSRect screenFrame = [_browserController visibleFrameForScreen:screen];

        NSRect windowFrame;
        NSString *windowWidth;
        NSString *windowHeight;
        NSInteger windowPositioning;
        BOOL blinkeredSiteWindow = NO;   // a separate full-window site window (not main/temp)
        if (mainBrowserWindow || self == self.browserController.mainBrowserWindow) {
            // This is the main browser window
            if (_isFullScreen) {
                // Full screen windows cover the whole screen
                windowWidth = @"100%";
                windowHeight = @"100%";
                windowPositioning = browserWindowPositioningCenter;
            } else {
                windowWidth = [preferences secureStringForKey:@"org_safeexambrowser_SEB_mainBrowserWindowWidth"];
                windowHeight = [preferences secureStringForKey:@"org_safeexambrowser_SEB_mainBrowserWindowHeight"];
                windowPositioning = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_mainBrowserWindowPositioning"];
            }
        } else if (temporaryWindow || (self.webView && self.webView == self.browserController.temporaryWebView)) {
            // This is a temporary browser window used for downloads with authentication
            windowWidth = @"1050";
            windowHeight = @"100%";
            windowPositioning = browserWindowPositioningCenter;
        } else {
            // This is another browser window
            blinkeredSiteWindow = YES;
            windowWidth = [preferences secureStringForKey:@"org_safeexambrowser_SEB_newBrowserWindowByLinkWidth"];
            windowHeight = [preferences secureStringForKey:@"org_safeexambrowser_SEB_newBrowserWindowByLinkHeight"];
            windowPositioning = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_newBrowserWindowByLinkPositioning"];
        }
        if ([windowWidth rangeOfString:@"%"].location == NSNotFound) {
            // Width is in pixels
            windowFrame.size.width = [windowWidth integerValue];
        } else {
            // Width is in percent
            windowFrame.size.width = ([windowWidth integerValue] * screenFrame.size.width) / 100;
        }
        if ([windowHeight rangeOfString:@"%"].location == NSNotFound) {
            // Height is in pixels
            windowFrame.size.height = [windowHeight integerValue];
        } else {
            // Height is in percent
            windowFrame.size.height = ([windowHeight integerValue] * screenFrame.size.height) / 100;
        }
        // Enforce minimum window size
        if (windowFrame.size.width < 394) windowFrame.size.width = 394;
        if (windowFrame.size.height < 247) windowFrame.size.height = 247;
        // Calculate x position according to positioning flag
        switch (windowPositioning) {
            case browserWindowPositioningLeft:
                windowFrame.origin.x = screenFrame.origin.x;
                break;
            case browserWindowPositioningCenter:
                windowFrame.origin.x = screenFrame.origin.x+(screenFrame.size.width-windowFrame.size.width) / 2;
                break;
            case browserWindowPositioningRight:
                windowFrame.origin.x = screenFrame.origin.x+screenFrame.size.width-windowFrame.size.width;
                break;
                
            default:
                //just in case set screen origin
                windowFrame.origin.x = screenFrame.origin.x;
                break;
        }

        // ── Blinkered split screen ───────────────────────────────────────────────────────
        // A split role overrides BOTH globals, and that is the whole point: width comes from
        // newBrowserWindowByLinkWidth above and x from newBrowserWindowByLinkPositioning via
        // the switch. An earlier revision of the plan named only the width one — overriding
        // it alone leaves both halves computing the SAME x and stacking on top of each other.
        //
        // Below 2x the 394pt minimum the split is not applied at all, rather than clamped:
        // the clamp above would silently un-halve each half back to 394, giving two windows
        // that overlap by (788 - usable) and overflow the screen edge. Falling through to the
        // normal full-width layout is stateless and self-correcting — the role is kept, so if
        // the usable width grows again the split resumes with no further signalling.
        if (blinkeredSiteWindow && self.blinkeredSplitRole != SEBBlinkeredSplitRoleNone) {
            CGFloat halfWidth = screenFrame.size.width / 2.0;
            if (halfWidth < 394) {
                DDLogWarn(@"[Blinkered] split role %ld not applied to window %ld: usable width %.0f "
                          @"is below 2x the 394pt minimum. Laying out full width instead.",
                          (long)self.blinkeredSplitRole, (long)self.windowNumber, screenFrame.size.width);
            } else {
                windowFrame.size.width = halfWidth;
                windowFrame.origin.x = (self.blinkeredSplitRole == SEBBlinkeredSplitRoleLeft)
                    ? screenFrame.origin.x
                    : screenFrame.origin.x + halfWidth;
            }
        }
        // Calculate y position: On top
        windowFrame.origin.y = screenFrame.origin.y + screenFrame.size.height - windowFrame.size.height;
        // Blinkered: keep full-window site windows below the home page's always-visible
        // top tab bar by leaving its strip free at the top (set by the page via setTopInset).
        extern CGFloat blinkeredTopInset;
        if (blinkeredSiteWindow && blinkeredTopInset > 0 &&
            windowFrame.size.height > screenFrame.size.height - blinkeredTopInset) {
            windowFrame.size.height = screenFrame.size.height - blinkeredTopInset;
            windowFrame.origin.y = screenFrame.origin.y;   // sit at the bottom, leaving the top strip
        }
        // Change Window size
        [self setFrame:windowFrame display:YES];
    }
}


// Overriding the sendEvent method allows blocking the context menu
// in the whole WebView, even in plugins
- (void)sendEvent:(NSEvent *)theEvent
{
	int controlKeyDown = [theEvent modifierFlags] & NSEventModifierFlagControl;
	// filter out right clicks
	if (!(([theEvent type] == NSEventTypeLeftMouseDown && controlKeyDown) ||
          [theEvent type] == NSEventTypeRightMouseDown)) {
        [super sendEvent:theEvent];
    } else {
        // Allow right mouse button/context menu according to setting
        // This is the only way how to block the context menu in WKWebView,
        // browser plugins and video players etc. (not on regular website elements in classic WebView)
        if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_enableRightMouseMac"]) {
            [super sendEvent:theEvent];
        }
    }
}


// Overriding this method without calling super in OS X 10.7 Lion
// prevents the windows' position and size to be restored on restarting the app
- (void)restoreStateWithCoder:(NSCoder *)coder
{
    DDLogVerbose(@"BrowserWindow %@: Prevented windows' position and size to be restored!", self);
    return;
}


- (void) startProgressIndicatorAnimation {
    
    if (!_progressIndicatorHolder) {
        _progressIndicatorHolder = [[NSView alloc] init];
        
        NSProgressIndicator *progressIndicator = [[NSProgressIndicator alloc] init];
        
        [progressIndicator setBezeled: NO];
        [progressIndicator setStyle: NSProgressIndicatorSpinningStyle];
        [progressIndicator setControlSize: NSControlSizeSmall];
        [progressIndicator sizeToFit];
        //[progressIndicator setUsesThreadedAnimation:YES];
        
        [_progressIndicatorHolder addSubview:progressIndicator];
        [_progressIndicatorHolder setFrame:progressIndicator.frame];
        [progressIndicator startAnimation:self];
        
        if (_isFullScreen) {
            [self addViewToTitleBar:_progressIndicatorHolder atRightOffset:20];
        } else {
            [self addViewToTitleBar:_progressIndicatorHolder atRightOffsetToTitle:10 verticalOffset:0];
        }
        
        [progressIndicator setFrame:NSMakeRect(
                                               
                                               0.5 * ([progressIndicator superview].frame.size.width - progressIndicator.frame.size.width),
                                               0.5 * ([progressIndicator superview].frame.size.height - progressIndicator.frame.size.height),
                                               
                                               progressIndicator.frame.size.width,
                                               progressIndicator.frame.size.height
                                               
                                               )];
        
        [progressIndicator setNextResponder:_progressIndicatorHolder];
        [_progressIndicatorHolder setNextResponder:self];
    } else {
        if (!_isFullScreen) {
            [self adjustPositionOfViewInTitleBar:_progressIndicatorHolder atRightOffsetToTitle:10 verticalOffset:0];
        }
    }
}

- (void) stopProgressIndicatorAnimation {
    
    [_progressIndicatorHolder removeFromSuperview];
    _progressIndicatorHolder = nil;
}


- (void) activateInitialFirstResponder
{
    if (self.toolbar.isVisible) {
        [self.browserWindowController activateInitialFirstResponder];
    } else {
        [self focusFirstElement];
    }
}

- (void) makeContentFirstResponder
{
    [self makeFirstResponder:(NSResponder *)[self nativeWebView]];
}

- (void) goToDock
{
    [self.browserController goToDock];
}

- (void)goBack
{
    [self.browserControllerDelegate goBack];
}

- (void)goForward
{
    [self.browserControllerDelegate goForward];
}

- (void)reload
{
    if (self.webView.isReloadAllowed) {
        if (self.webView.showReloadWarning) {
            DDLogInfo(@"Show Reload Current Page warning.");
            // Display warning and ask if to reload page
            NSAlert *newAlert = [self.browserController.sebController newAlert];
            [newAlert setMessageText:NSLocalizedString(@"Reload Current Page", @"")];
            [newAlert setInformativeText:NSLocalizedString(@"Do you really want to reload the current web page?", @"")];
            [newAlert addButtonWithTitle:NSLocalizedString(@"Reload", @"")];
            [newAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
            [newAlert setAlertStyle:NSAlertStyleWarning];
            
            void (^conditionalReload)(NSModalResponse) = ^void (NSModalResponse answer) {
                [self.browserController.sebController removeAlertWindow:newAlert.window];
                switch(answer) {
                    case NSAlertFirstButtonReturn:
                        [self unconditionallyReload];
                        break;
                    
                        
                    default:
                        DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld. Not reloading.", (long)answer);
                    case NSAlertSecondButtonReturn:
                        // Return without reloading page
                        return;
                }
            };
            
            [self.browserController.sebController runModalAlert:newAlert conditionallyForWindow:self completionHandler:conditionalReload];
            
        } else {
            // Reload page without displaying warning
            [self unconditionallyReload];
        }
    }
}

- (void)unconditionallyReload
{
    // Reset the list of dismissed URLs and the dismissAll flag
    // (for the Teach allowed/blocked URLs mode)
    SEBAbstractWebView *creatingWebView = [self.webView creatingWebView];
    if (!creatingWebView) {
        creatingWebView = self.webView;
    }
    [creatingWebView.notAllowedURLs removeAllObjects];
    creatingWebView.dismissAll = NO;
    
    // Reload page
    DDLogInfo(@"Reloading current webpage");
    [self.browserControllerDelegate reload];
}


- (void) focusFirstElement
{
    [self.browserControllerDelegate focusFirstElement];
}

- (void) focusLastElement
{
    [self.browserControllerDelegate focusLastElement];
}


- (void)zoomPageIn:(id)sender
{
    [self zoomPageIn];
}

- (void)zoomPageOut:(id)sender
{
    [self zoomPageOut];
}

- (void)resetPageZoom:(id)sender
{
    [self zoomPageReset];
}


- (void)zoomPageIn
{
    [self.browserControllerDelegate zoomPageIn];
}


- (void)zoomPageOut
{
    [self.browserControllerDelegate zoomPageOut];
}


- (void)zoomPageReset
{
    [self.browserControllerDelegate zoomPageReset];
}


- (void)makeTextLarger:(id)sender
{
    [self textSizeIncrease];
}

- (void)makeTextSmaller:(id)sender
{
    [self textSizeDecrease];
}

- (void)makeTextStandardSize:(id)sender
{
    [self textSizeReset];
}


- (void)textSizeIncrease
{
    [self.browserControllerDelegate textSizeIncrease];
}


- (void)textSizeDecrease
{
    [self.browserControllerDelegate textSizeDecrease];
}


- (void)textSizeReset
{
    [self.browserControllerDelegate textSizeReset];
}


- (void) privateCopy:(id)sender
{
    [self.browserControllerDelegate privateCopy:sender];
}

- (void) privateCut:(id)sender
{
    [self.browserControllerDelegate privateCut:sender];
}

- (void) privatePaste:(id)sender
{
    [self.browserControllerDelegate privatePaste:sender];
}


#pragma mark URL Filter Blocked Message

- (void) showURLFilterMessage {
    
    if (!_filterMessageHolder) {
        
        NSRect frameRect = NSMakeRect(0,0,155,21); // This will change based on the size you need
        NSTextField *message = [[NSTextField alloc] initWithFrame:frameRect];
        message.bezeled = NO;
        message.editable = NO;
        message.drawsBackground = NO;
        [message.cell setUsesSingleLineMode:YES];
        CGFloat messageLabelYOffset = 0;
        
        NSString *messageString;
        
        // Set message for URL blocked according to settings
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        switch ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_URLFilterMessage"]) {
                
            case URLFilterMessageText:
                message.stringValue = NSLocalizedString(@"URL Blocked!", @"");
                [message setFont:[NSFont boldSystemFontOfSize:15]];   // was smallSystemFontSize — bigger, easier to notice
                [message setTextColor:[NSColor redColor]];
                break;
                
            case URLFilterMessageX:
                message.stringValue = @"✕";
                [message setFont:[NSFont boldSystemFontOfSize:_isFullScreen ? 16 : 20]];
                [message setTextColor:[NSColor blackColor]];
                messageLabelYOffset = _isFullScreen ? 0 : 4;
                break;
        }
        
        NSButton *URLBlockedButton = [NSButton new];
        URLBlockedButton.title = messageString;
        [URLBlockedButton setButtonType:NSMomentaryLightButton];
        
        NSSize messageLabelSize = [message intrinsicContentSize];
        [message setAlignment:NSTextAlignmentRight];
        CGFloat messageLabelWidth = messageLabelSize.width + 2;
        CGFloat messageLabelHeight = messageLabelSize.height;
        [message setFrameSize:NSMakeSize(messageLabelWidth, messageLabelHeight)];
        
        _filterMessageHolder = [[NSView alloc] initWithFrame:message.frame];
        [_filterMessageHolder addSubview:message];
        [_filterMessageHolder setContentHuggingPriority:NSLayoutPriorityFittingSizeCompression-1.0 forOrientation:NSLayoutConstraintOrientationVertical];
        
        [message setFrame:NSMakeRect(
                                     
                                     0.5 * ([message superview].frame.size.width - message.frame.size.width),
                                     (0.5 * ([message superview].frame.size.height - message.frame.size.height)) + messageLabelYOffset,
                                     
                                     message.frame.size.width,
                                     message.frame.size.height
                                     
                                     )];
        
        [message setNextResponder:_filterMessageHolder];
        
    }
    
    // Show the message
    if (_isFullScreen) {
        [self showURLBlockedHUD];
    } else {
        [self addViewToTitleBar:_filterMessageHolder atRightOffset:5];
        [_filterMessageHolder setNextResponder:self];
        
        // Remove the URL filter message after a delay
        [self performSelector:@selector(hideURLFilterMessage) withObject: nil afterDelay: 1];
    }
}

- (void) hideURLFilterMessage {
    
    [self.filterMessageHolder removeFromSuperview];
}


- (void) showURLBlockedHUD
{
    if (!_filterMessageHUD) {
        
        NSRect messageRect = _filterMessageHolder.frame;
        CGFloat horizontalPadding = 8.0;
        CGFloat verticalPadding = 5.0;
        
        NSRect backgroundRect = NSMakeRect(0, 0, messageRect.size.width+horizontalPadding*2, messageRect.size.height+verticalPadding*2);
        NSView *HUDBackground = [[NSView alloc] initWithFrame:backgroundRect];
        HUDBackground.wantsLayer = true;
        HUDBackground.layer.cornerRadius = MIN(horizontalPadding, verticalPadding);
        if (@available(macOS 10.8, *)) {
            HUDBackground.layer.backgroundColor = [NSColor lightGrayColor].CGColor;
        }
        
        [HUDBackground addSubview:_filterMessageHolder];
        [_filterMessageHolder setFrameOrigin:NSMakePoint(horizontalPadding, verticalPadding)];
        
        _filterMessageHUD = [[HUDPanel alloc] initWithContentRect:HUDBackground.bounds styleMask:NSWindowStyleMaskBorderless backing:NSBackingStoreBuffered defer:false];
        _filterMessageHUD.backgroundColor = [NSColor clearColor];
        _filterMessageHUD.opaque = false;
        _filterMessageHUD.alphaValue = 0.92;   // was 0.75 — less transparent, stands out more
        
        _filterMessageHUD.contentView = HUDBackground;
    }
    NSRect visibleScreenRect = self.screen.usableFrame;
    NSPoint topLeftPoint;
    topLeftPoint.x = visibleScreenRect.origin.x + 42;   // top-LEFT (was top-right) — more visible; people read left-first
    topLeftPoint.y = visibleScreenRect.origin.y + visibleScreenRect.size.height - 3;
    [_filterMessageHUD setFrameTopLeftPoint:topLeftPoint];
    
    _filterMessageHUD.becomesKeyOnlyIfNeeded = YES;
    [_filterMessageHUD setLevel:NSModalPanelWindowLevel];
    DDLogDebug(@"Opening URL blocked HUD: %@", _filterMessageHUD);
    [_filterMessageHUD makeKeyAndOrderFront:nil];
    [_filterMessageHUD invalidateShadow];
    
    // Hide the HUD filter message after a delay
    [self performSelector:@selector(hideURLBlockedHUD) withObject: nil afterDelay: 1];
}


- (void) hideURLBlockedHUD
{
    [_filterMessageHUD orderOut:self];
}


#pragma mark URL Filter Teaching Mode Alert

- (BOOL) showURLFilterAlertSheetForWindow:(NSWindow *)window
                               forRequest:(NSURLRequest *)request
                         forContentFilter:(BOOL)contentFilter
                           filterResponse:(URLFilterRuleActions)filterResponse
{
    if (!window.attachedSheet) {
        SEBAbstractWebView *creatingWebView = [self.webView creatingWebView];
        if (!creatingWebView) {
            creatingWebView = self.webView;
        }
        
        // If the filter Response isn't block and the URL filter learning mode is switched on
        if (filterResponse != URLFilterActionBlock && [SEBURLFilter sharedSEBURLFilter].learningMode) {
            
            // Check if all non-allowed URLs should be dismissed in the current webview
            if (creatingWebView.dismissAll == NO) {
                NSURL *resourceURL = request.URL;
                self.URLFilterAlertURL = resourceURL;
                if (!creatingWebView.notAllowedURLs) {
                    creatingWebView.notAllowedURLs = [NSMutableArray new];
                }
                // Check if the non-allowed URL has been dismissed for the current webview
                BOOL containsURL = NO;
                for (NSURL *notAllowedURL in creatingWebView.notAllowedURLs) {
                    if ([resourceURL isEqualTo:notAllowedURL]) {
                        containsURL = YES;
                        break;
                    }
                }
                if (containsURL == NO) {
                    
                    // Check if the non-allowed URL is in the ignore list for current settings
                    if (![[SEBURLFilter sharedSEBURLFilter] testURLIgnored:resourceURL]) {
                        
                        // This non-allowed URL hasn't been dismissed yet, add it to the dismissed list
                        [creatingWebView.notAllowedURLs addObject:resourceURL];
                        
                        // Set filter alert text depending if a URL or content was blocked
                        if (contentFilter) {
                            self.URLFilterAlertText.stringValue = NSLocalizedString(@"This embedded resource isn't allowed! You can create a new filter rule based on the following patterns:", @"");
                        } else {
                            self.URLFilterAlertText.stringValue = NSLocalizedString(@"It's not allowed to open this URL! You can create a new filter rule based on the following patterns:", @"");
                        }
                        // Set filter expression according to selected pattern in the NSMatrix radio button group
                        [self changedFilterPattern:self.filterPatternMatrix];
                        
                        // Set full URL in the filter expression text field, trim a possible trailing "/"
                        self.filterExpressionField.string = [self.URLFilterAlertURL.absoluteString stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]];
                        
                        // Set the domain pattern label/button string
                        self.domainPatternButton.title = [self filterExpressionForPattern:SEBURLFilterAlertPatternDomain];
                        
                        // Set the host pattern label/button string
                        self.hostPatternButton.title = [self filterExpressionForPattern:SEBURLFilterAlertPatternHost];
                        
                        // Set the host/path pattern label/button string
                        self.hostPathPatternButton.title = [self filterExpressionForPattern:SEBURLFilterAlertPatternHostPath];
                        
                        // Set the directory pattern label/button string
                        self.directoryPatternButton.title = [self filterExpressionForPattern:SEBURLFilterAlertPatternDirectory];
                        
                        // If the (main) browser window is full screen, we don't show the dialog as sheet
                        if (window && self.browserController.mainBrowserWindow.isFullScreen && window == self.browserController.mainBrowserWindow) {
                            window = nil;
                        }
                        
                        if (@available(macOS 12.0, *)) {
                        } else {
                            if (@available(macOS 11.0, *)) {
                                if (!window && (self.browserController.sebController.isAACEnabled || self.browserController.sebController.wasAACEnabled)) {
                                    window = self.browserController.mainBrowserWindow;
                                }
                            }
                        }
                        
                        [NSApp beginSheet: self.URLFilterAlert
                           modalForWindow: window
                            modalDelegate: nil
                           didEndSelector: nil
                              contextInfo: nil];
                        NSInteger returnCode = [NSApp runModalForWindow: self.URLFilterAlert];
                        // Dialog is up here.
                        [NSApp endSheet: self.URLFilterAlert];
                        [NSApp abortModal];
                        [self.URLFilterAlert orderOut: self];
                        switch (returnCode) {
                            case SEBURLFilterAlertDismiss:
                                return NO;
                                
                            case SEBURLFilterAlertAllow:
                                // Allow URL (in filter learning mode)
                                [[SEBURLFilter sharedSEBURLFilter] addRuleAction:URLFilterActionAllow withFilterExpression:[SEBURLFilterExpression filterExpressionWithString:self.filterExpression]];
                                return YES;
                                
                            case SEBURLFilterAlertIgnore:
                                // Ignore URL according to selected pattern (in filter learning mode)
                                [[SEBURLFilter sharedSEBURLFilter] addRuleAction:URLFilterActionIgnore withFilterExpression:[SEBURLFilterExpression filterExpressionWithString:self.filterExpression]];
                                return NO;
                                
                            case SEBURLFilterAlertBlock:
                                // Block URL (in filter learning mode)
                                [[SEBURLFilter sharedSEBURLFilter] addRuleAction:URLFilterActionBlock withFilterExpression:[SEBURLFilterExpression filterExpressionWithString:self.filterExpression]];
                                return NO;
                                
                            case SEBURLFilterAlertDismissAll:
                                return NO;
                                
                        }
                    }
                }
            }
        } else if (contentFilter == NO) {
            // The filter Response is block or the URL filter learning mode isn't switched on
            // Display "URL Blocked" (or red "X") top/right in window title bar
            [self showURLFilterMessage];
        }
    }
    return NO;
}


- (IBAction)clickedDomainPattern:(id)sender
{
    self.filterExpression = [self filterExpressionForPattern:SEBURLFilterAlertPatternDomain];
    self.filterExpressionField.string = self.filterExpression;
}

- (IBAction)clickedHostPattern:(id)sender
{
    self.filterExpression = [self filterExpressionForPattern:SEBURLFilterAlertPatternHost];
    self.filterExpressionField.string = self.filterExpression;
}

- (IBAction)clickedHostPathPattern:(id)sender
{
    self.filterExpression = [self filterExpressionForPattern:SEBURLFilterAlertPatternHostPath];
    self.filterExpressionField.string = self.filterExpression;
}

- (IBAction)clickedDirectoryPattern:(id)sender
{
    self.filterExpression = [self filterExpressionForPattern:SEBURLFilterAlertPatternDirectory];
    self.filterExpressionField.string = self.filterExpression;
}

- (IBAction)clickedFullURLPattern:(id)sender {
    self.filterExpression = self.URLFilterAlertURL.absoluteString;
    self.filterExpressionField.string = self.filterExpression;
}


- (IBAction) URLFilterAlertDismiss: (id)sender {
    [NSApp stopModalWithCode:SEBURLFilterAlertDismiss];
}

- (IBAction) URLFilterAlertAllow: (id)sender {
    [NSApp stopModalWithCode:SEBURLFilterAlertAllow];
}

- (IBAction) URLFilterAlertIgnore: (id)sender {
    [NSApp stopModalWithCode:SEBURLFilterAlertIgnore];
}

- (IBAction) URLFilterAlertBlock: (id)sender {
    [NSApp stopModalWithCode:SEBURLFilterAlertBlock];
}

- (IBAction) URLFilterAlertIgnoreAll: (id)sender {
    if (self.webView.creatingWebView) {
        self.webView.creatingWebView.dismissAll = YES;
    } else {
        self.webView.dismissAll = YES;
    }
    [NSApp stopModalWithCode:SEBURLFilterAlertDismissAll];
}


- (IBAction)editingFilterExpression:(NSTextField *)sender {
    self.filterExpression = self.filterExpressionField.string;
}


- (void)textDidChange:(NSNotification *)aNotification
{
    [self.filterPatternMatrix selectCellAtRow:SEBURLFilterAlertPatternCustom column:0];
    self.filterExpression = self.filterExpressionField.string;
}

- (IBAction)changedFilterPattern:(NSMatrix *)sender
{
    NSUInteger selectedFilterPattern = [sender selectedRow];
    
    self.filterExpression = [self filterExpressionForPattern:selectedFilterPattern];
}


- (NSString *)filterExpressionForPattern:(SEBURLFilterAlertPattern)filterPattern
{
    NSString *domain = [self.URLFilterAlertURL registeredDomain];
    if (!domain) {
        domain = @"";
    }
    
    NSString *host = self.URLFilterAlertURL.host;
    if (host.length == 0) {
        host = [self.URLFilterAlertURL.scheme stringByAppendingString:@":"];
    }
    NSString *path = self.URLFilterAlertURL.path;
    if (!path || [path isEqualToString:@"/"]) {
        path = @"";
    }
    NSString *directory = @"";
    if (self.URLFilterAlertURL.pathExtension.length > 0) {
        NSMutableArray *pathComponents = [NSMutableArray arrayWithArray:self.URLFilterAlertURL.pathComponents];
        if (pathComponents.count > 2) {
            [pathComponents removeObjectAtIndex:0];
            [pathComponents removeLastObject];
            directory = [pathComponents componentsJoinedByString:@"/"];
            directory = [NSString stringWithFormat:@"/%@/*", directory];
        } else if (pathComponents.count == 2) {
            directory = @"/*";
        }
    } else {
        if (path.length > 1) {
            directory = [NSString stringWithFormat:@"%@/*", path];
        }
    }
    
    
    switch (filterPattern) {
            
        case SEBURLFilterAlertPatternDomain:
            return domain;
            
        case SEBURLFilterAlertPatternHost:
            return host;
            
        case SEBURLFilterAlertPatternHostPath: {
            return [NSString stringWithFormat:@"%@%@", host, path];
        }
            
        case SEBURLFilterAlertPatternDirectory: {
            return [NSString stringWithFormat:@"%@%@", host, directory];
        }
            
        case SEBURLFilterAlertPatternCustom:
            return self.filterExpressionField.string;
    }
    
    return @"";
}


- (void) alertDidEnd:(NSAlert *)alert
          returnCode:(NSInteger)returnCode
         contextInfo:(void *)contextInfo
{
    // If the URL filter learning mode is switched on, handle the first button differently
    if (returnCode == NSAlertFirstButtonReturn && [SEBURLFilter sharedSEBURLFilter].learningMode) {
        // Allow URL (in filter learning mode)
        [alert.window orderOut:self];
        return;
    }
    [alert.window orderOut:self];
}


#pragma mark Overriding NSWindow Methods

// This method is called by NSWindow’s zoom: method while determining the frame a window may be zoomed to
// We override the size calculation to take SEB Dock in account if it's displayed
- (NSRect)windowWillUseStandardFrame:(NSWindow *)window
                        defaultFrame:(NSRect)newFrame {
    // Check if SEB Dock is displayed and reduce visibleFrame accordingly
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    
    // Get frame of the usable screen (considering if menu bar is enabled)
    NSRect screenFrame = self.screen.usableFrame;
    newFrame.size.height = screenFrame.size.height;
    
    if ((!_browserController.mainBrowserWindow || self.screen == _browserController.mainBrowserWindow.screen) && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_showTaskBar"]) {
        CGFloat dockHeight = [preferences secureDoubleForKey:@"org_safeexambrowser_SEB_taskBarHeight"];
        newFrame.origin.y += dockHeight;
        newFrame.size.height -= dockHeight;
    }
    return newFrame;
}


#pragma mark - SEBAbstractBrowserControllerDelegate Methods

- (nonnull id)nativeWebView {
    return [self.browserControllerDelegate nativeWebView];

}


- (nullable NSURL *)url {
    return [self.browserControllerDelegate url];
}


- (nullable NSString *)pageTitle {
    return [self.browserControllerDelegate pageTitle];
}


- (BOOL)canGoBack {
    return [self.browserControllerDelegate canGoBack];
}


- (BOOL)canGoForward {
    return [self.browserControllerDelegate canGoForward];
}


- (void)loadURL:(nonnull NSURL *)url {
    [self.browserControllerDelegate loadURL:url];
}


- (void)stopLoading {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self setLoading:NO];
    });
}


- (void) searchText:(NSString *)textToSearch backwards:(BOOL)backwards caseSensitive:(BOOL)caseSensitive
{
    [self.browserControllerDelegate searchText:textToSearch backwards:backwards caseSensitive:caseSensitive];
}


- (void) searchTextMatchFound:(BOOL)matchFound
{
    [self.browserWindowController searchTextMatchFound:matchFound];
}


- (void)setDownloadingSEBConfig:(BOOL)downloadingSEBConfig {
    self.browserControllerDelegate.downloadingSEBConfig = downloadingSEBConfig;
}


#pragma mark SEBAbstractWebViewNavigationDelegate Methods

- (WKWebViewConfiguration *) wkWebViewConfiguration
{
    return self.browserController.wkWebViewConfiguration;
}

- (id<WKScriptMessageHandler>) blinkeredScriptMessageHandler
{
    if ([self.browserController respondsToSelector:@selector(blinkeredScriptMessageHandler)]) {
        return self.browserController.blinkeredScriptMessageHandler;
    }
    return nil;
}

- (id) accessibilityDock
{
    return self.browserController.accessibilityDock;
}


- (void) setPageTitle:(NSString *)title
{
    [self sebWebViewDidUpdateTitle:title];
}


- (void) setLoading:(BOOL)loading
{
    if (loading) {
        [self startProgressIndicatorAnimation];
    } else {
        [self stopProgressIndicatorAnimation];
    }
    [self.browserController setLoading:loading];
}

- (void) setCanGoBack:(BOOL)canGoBack canGoForward:(BOOL)canGoForward
{
    // Enable back/forward buttons according to availablility for this webview
    NSSegmentedControl *backForwardButtons = [self.browserWindowController backForwardButtons];
    [backForwardButtons setEnabled:canGoBack forSegment:0];
    [backForwardButtons setEnabled:canGoForward forSegment:1];
    
    [self.browserController setCanGoBack:canGoBack canGoForward:canGoForward];
}

- (void) examineCookies:(NSArray<NSHTTPCookie *>*)cookies forURL:(NSURL *)url
{
    [self.browserController examineCookies:cookies forURL:url];
}

- (void) examineHeaders:(NSDictionary<NSString *,NSString *>*)headerFields forURL:(NSURL *)url
{
    [self.browserController examineHeaders:headerFields forURL:url];
}

- (void) firstDOMElementDeselected
{
    if (!self.toolbar.isVisible) {
        [self.browserController firstDOMElementDeselected];
    }
}

- (void) lastDOMElementDeselected
{
    if (!self.toolbar.isVisible) {
        [self.browserController lastDOMElementDeselected];
    }
}

- (SEBAbstractWebView *) openNewTabWithURL:(NSURL *)url
                             configuration:(WKWebViewConfiguration *)configuration
{
    // A page in THIS window is opening the new one — hand our windowNumber to the controller
    // so it can stamp the new window's blinkeredOpenerWindowNumber (grouping for the tab bar).
    self.browserController.blinkeredPendingOpenerWindowNumber = self.windowNumber;
    return [self.browserController openNewTabWithURL:url configuration:configuration];
}

- (SEBAbstractWebView *) openNewWebViewWindowWithURL:(NSURL *)url
                                       configuration:(WKWebViewConfiguration *)configuration
{
    self.browserController.blinkeredPendingOpenerWindowNumber = self.windowNumber;
    return [self.browserController openNewWebViewWindowWithURL:url configuration:configuration];
}

- (void) makeActiveAndOrderFront
{
    [self makeKeyAndOrderFront:self];
}

- (void) showWebView:(SEBAbstractWebView *)webView
{
    [self.browserController showWebView:webView];
}

- (void) closeWebView
{
    [self.browserController closeWebView:self.abstractWebView];
}

- (void) closeWebView:(SEBAbstractWebView *)webView
{
    [self.browserController closeWebView:webView];
}

- (void) addWebView:(id)nativeWebView
{
    [self.contentView addSubview:nativeWebView];
    [self addConstraintsToWebView:(NSView *)nativeWebView];
}


- (NSString *)currentMainHost
{
    return self.browserController.currentMainHost;
}

- (void)setCurrentMainHost:(NSString *)currentMainHost
{
    self.browserController.currentMainHost = currentMainHost;
}

- (BOOL) isMainBrowserWebViewActive
{
    return self.webView.isMainBrowserWebView;
}

- (BOOL) isNavigationAllowed
{
    if (self.webView) {
        return self.webView.isNavigationAllowed;
    } else {
        return [self isNavigationAllowedMainWebView:self.browserController.isMainBrowserWebViewActive];
    }
}

- (BOOL) isNavigationAllowedMainWebView:(BOOL)mainWebView
{
    return [self.browserController isNavigationAllowedMainWebView:mainWebView];
}

- (BOOL) isReloadAllowed
{
    if (self.webView) {
        return self.webView.isReloadAllowed;
    } else {
        return [self isReloadAllowedMainWebView:self.browserController.isMainBrowserWebViewActive];
    }
}

- (BOOL) isReloadAllowedMainWebView:(BOOL)mainWebView
{
    return [self.browserController isReloadAllowedMainWebView:mainWebView];
}

- (BOOL) showReloadWarning
{
    if (self.webView) {
        return self.webView.showReloadWarning;
    } else {
        return [self showReloadWarningMainWebView:self.browserController.isMainBrowserWebViewActive];
    }
}

- (BOOL) showReloadWarningMainWebView:(BOOL)mainWebView
{
    return [self.browserController showReloadWarningMainWebView:mainWebView];
}

- (NSString *) webPageTitle:(NSString *)title orURL:(NSURL *)url mainWebView:(BOOL)mainWebView
{
    return [self.browserController webPageTitle:title orURL:url mainWebView:mainWebView];
}

- (NSString *)quitURL
{
    return self.browserController.quitURL;
}

- (NSString *)pageJavaScript
{
    return self.browserController.pageJavaScript;
}

- (BOOL)allowDownloads
{
    return self.browserController.allowDownloads;
}

- (BOOL)allowUploads
{
    return self.browserController.allowUploads;
}

- (void)showAlertNotAllowedDownUploading:(BOOL)uploading
{
    [self.browserController showAlertNotAllowedDownUploading:uploading];
}

- (void)showAlertNotAllowedDownloadingAndOpeningSebConfig:(BOOL)downloading
{
    [self.browserController showAlertNotAllowedDownloadingAndOpeningSebConfig:downloading];
}

- (BOOL)overrideAllowSpellCheck
{
    return self.browserController.overrideAllowSpellCheck;
}

- (BOOL)isUsingServerBEK
{
    return self.browserController.isUsingServerBEK;
}

- (NSURLRequest *)modifyRequest:(NSURLRequest *)request
{
    return [self.browserController modifyRequest:request];
}

- (NSString *) browserExamKeyForURL:(NSURL *)url
{
    return [self.browserController browserExamKeyForURL:url];
}

- (NSString *) configKeyForURL:(NSURL *)url
{
    return [self.browserController configKeyForURL:url];
}

- (NSString *) appVersion
{
    return [self.browserController appVersion];
}


@synthesize customSEBUserAgent;

- (NSString *) customSEBUserAgent
{
    return self.browserController.customSEBUserAgent;
    
}


- (NSArray <NSData *> *) privatePasteboardItems
{
    return self.browserController.privatePasteboardItems;
}

- (void) setPrivatePasteboardItems:(NSArray<NSData *> *)privatePasteboardItems
{
    self.browserController.privatePasteboardItems = privatePasteboardItems;
}


- (void) presentAlertWithTitle:(NSString *)title
                       message:(NSString *)message
{
    [self.browserController presentAlertWithTitle:title message:message];
}


- (id) window
{
    return self;
}

- (BOOL) isAACEnabled
{
    return self.browserController.isAACEnabled;
}


- (void)sebWebViewDidStartLoad
{
    [self setLoading:YES];
}

// Launch cleanup #4/#5: window stays black (content view hidden) until the first
// page painted. The window itself stays in place and key — sheets, focus and the
// kiosk logic are unaffected; only the white pre-paint content area is hidden.
static const NSTimeInterval blinkeredContentRevealSafetyTimeout = 15;

// P1 Bug-A: expose the hold-black state so the paint detector never fires on a DESIGNED black.
- (BOOL)blinkeredContentHeld { return _blinkeredContentHeld; }

// Proposal B (MAC_WAKE_EDGE_RECOVERY_PLAN.md §2): the home-lock brand backdrop. Matches the lock
// page's own background (#1a1a2e) so any paint failure reads as "lock screen missing its live
// content" instead of a void black that looks like a bricked Mac. Pure AppKit — nothing here can
// be taken down by a WebContent death. sharingType is untouched anywhere in this feature
// (review condition 2): what capture sees is unchanged, only what the USER sees.
+ (NSColor *) blinkeredBrandBackdropColor
{
    return [NSColor colorWithSRGBRed:0x1a/255.0 green:0x1a/255.0 blue:0x2e/255.0 alpha:1.0];
}

// LAUNCH-TIME home-lock predicate. blinkeredHomeSessionInfo (home_session.json) is timing-blind
// at launch: the file is written by the /seb-sethomesession redirect the lock page loads THROUGH
// — i.e. AFTER the hold overlay and covers are already up — and the agent deletes it on every
// unlock, so on a fresh lock the hold/covers always read "not home" and fell back to black
// (field-confirmed on Maggie B's Mac, 3.6.176, 4 Aug). The config's startURL is the correct
// launch-time signal: HOME locks uniquely start at .../seb-sethomesession?...&to=<content>
// (server launch.seb); focus sessions start at /home/:id/focus-content and class sessions at
// /class/... — neither matches, so both keep pure black, as do school exam configs.
+ (BOOL) blinkeredIsHomeLockSession
{
    NSString *startURL = [[NSUserDefaults standardUserDefaults] secureStringForKey:@"org_safeexambrowser_SEB_startURL"];
    return startURL != nil && [startURL rangeOfString:@"/seb-sethomesession"].location != NSNotFound;
}

// LAUNCH-TIME Focus predicate. Focus is the THIRD Blinkered session shape and it matches neither
// half of blinkeredIsHomeLockSession, deliberately: the server routes Focus around
// /seb-sethomesession — "Focus isn't a home lock, so we don't want the native home_session.json
// written (that drives the offline re-lock / force-quit watchdog)" (seb-classroom/server.js) — so
// the start URL does not match AND the session file is intentionally absent.
//
// Matched on the parsed PATH, not with a substring search over the whole URL: a class session's
// start URL carries focus-related QUERY parameters (fsid/fexp/fdur) and must never be mistaken for
// one. An unparseable URL yields nil and therefore NO — today's behaviour, the safe side.
+ (BOOL) blinkeredIsFocusSession
{
    NSString *startURL = [[NSUserDefaults standardUserDefaults] secureStringForKey:@"org_safeexambrowser_SEB_startURL"];
    if (!startURL.length) return NO;
    return [[NSURL URLWithString:startURL].path hasSuffix:@"/focus-content"];
}

+ (void) blinkeredAddBrandBackdropContentToView:(NSView *)view
{
    // C8: the default wording, and the one the launch hold uses. It claims no schedule and no end
    // time, so it is true of a server-minted MANUAL lock, an agent-minted offline lock and a
    // scheduled one alike. Changing it means re-reading C8 and review F8 first.
    [self blinkeredAddBrandBackdropContentToView:view
                                           title:NSLocalizedString(@"Locked by Blinkered", @"")
                                          detail:nil];
}

// `detail` is an optional smaller second line. It exists for Focus, where "Locked by Blinkered"
// would be a lie and where — because Focus has no offline panel — this surface is the only thing
// that can name the way out. Home locks pass nil: their panel names it, and this screen faces the
// kid as well as the parent.
+ (void) blinkeredAddBrandBackdropContentToView:(NSView *)view
                                          title:(NSString *)title
                                         detail:(NSString *)detail
{
    view.wantsLayer = YES;
    view.layer.backgroundColor = [self blinkeredBrandBackdropColor].CGColor;

    const CGFloat iconSide = 96;
    const CGFloat gap = 16;
    const CGFloat detailGap = 8;

    NSImageView *iconView = [[NSImageView alloc] initWithFrame:NSMakeRect(0, 0, iconSide, iconSide)];
    iconView.image = [NSApp applicationIconImage];
    iconView.imageScaling = NSImageScaleProportionallyUpOrDown;

    NSTextField *label = [NSTextField labelWithString:title];
    label.font = [NSFont systemFontOfSize:16 weight:NSFontWeightMedium];
    label.textColor = [NSColor colorWithSRGBRed:1 green:1 blue:1 alpha:0.55];
    [label sizeToFit];

    NSTextField *detailLabel = nil;
    if (detail.length) {
        detailLabel = [NSTextField labelWithString:detail];
        detailLabel.font = [NSFont systemFontOfSize:13 weight:NSFontWeightRegular];
        detailLabel.textColor = [NSColor colorWithSRGBRed:1 green:1 blue:1 alpha:0.40];
        [detailLabel sizeToFit];
    }

    // Centre the icon-over-label(-over-detail) block; flexible margins keep it centred across
    // resizes and the differing cover/browser window geometries.
    NSRect b = view.bounds;
    CGFloat detailBlock = detailLabel ? NSHeight(detailLabel.frame) + detailGap : 0;
    CGFloat blockHeight = iconSide + gap + NSHeight(label.frame) + detailBlock;
    CGFloat y = NSMidY(b) - blockHeight / 2;
    if (detailLabel) {
        detailLabel.frame = NSMakeRect(NSMidX(b) - NSWidth(detailLabel.frame) / 2, y,
                                       NSWidth(detailLabel.frame), NSHeight(detailLabel.frame));
        detailLabel.autoresizingMask = NSViewMinXMargin | NSViewMaxXMargin | NSViewMinYMargin | NSViewMaxYMargin;
        [view addSubview:detailLabel];
        y += NSHeight(detailLabel.frame) + detailGap;
    }
    label.frame = NSMakeRect(NSMidX(b) - NSWidth(label.frame) / 2, y,
                             NSWidth(label.frame), NSHeight(label.frame));
    iconView.frame = NSMakeRect(NSMidX(b) - iconSide / 2, y + NSHeight(label.frame) + gap,
                                iconSide, iconSide);
    iconView.autoresizingMask = NSViewMinXMargin | NSViewMaxXMargin | NSViewMinYMargin | NSViewMaxYMargin;
    label.autoresizingMask = NSViewMinXMargin | NSViewMaxXMargin | NSViewMinYMargin | NSViewMaxYMargin;
    [view addSubview:iconView];
    [view addSubview:label];
}

- (void) blinkeredHoldContentUntilFirstPaint
{
    if (_blinkeredContentHeld) {
        return;
    }
    _blinkeredContentHeld = YES;
    // Proposal B: HOME locks hold on the brand backdrop; exam/class (AAC + classic SEB) keep the
    // original pure black (review condition 1 — proctoring optics unchanged). The flash
    // suppression comes from the overlay's PRESENCE, not its colour, so hold/reveal timing is
    // identical in both branches (review condition 5). Predicate = launch-time startURL check
    // (see blinkeredIsHomeLockSession — the reviewed home_session.json predicate is timing-blind
    // at launch), OR'd with the session file for belt-and-braces mid-session robustness.
    BOOL homeLock = [SEBBrowserWindow blinkeredIsHomeLockSession]
        || [self.browserController.sebController blinkeredHomeSessionInfo] != nil;
    self.backgroundColor = homeLock ? [SEBBrowserWindow blinkeredBrandBackdropColor] : [NSColor blackColor];
    NSView *overlay = [[NSView alloc] initWithFrame:self.contentView.bounds];
    overlay.wantsLayer = YES;
    overlay.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    if (homeLock) {
        [SEBBrowserWindow blinkeredAddBrandBackdropContentToView:overlay];
    } else {
        overlay.layer.backgroundColor = NSColor.blackColor.CGColor;
    }
    [self.contentView addSubview:overlay positioned:NSWindowAbove relativeTo:nil];
    _blinkeredHoldOverlay = overlay;
    // Safety net: never leave the window black forever if neither the finish nor
    // the fail callback ever arrives.
    //
    // STAGE 3 cause 1 — the MODES are load-bearing, and their absence made all of Stage 2 inert.
    // performSelector:withObject:afterDelay: schedules the perform in NSDefaultRunLoopMode ONLY.
    // The offline panel is an app-modal alert (SEBController -runModalAlert:conditionallyForWindow:
    // ends in [alert runModal]), which spins the run loop in NSModalPanelRunLoopMode — so in the one
    // device state this timeout exists FOR, the perform could not fire while the panel was up. It
    // fired the instant the panel was dismissed: 43.2 s, 16.1 s and 205 s after launch across three
    // rig runs against a nominal 15 s, every one within 261 ms of the user pressing Retry (plan §5
    // STAGE 3). Scheduling in the common modes is what makes 15 s mean 15 s.
    //
    // NSRunLoopCommonModes is documented to include the modal-panel and event-tracking modes in an
    // AppKit app — and both are ALSO named explicitly rather than assumed, because assuming
    // framework semantics is what produced every defect in this workstream. Naming a mode twice is
    // harmless: the perform is one request and fires once, in whichever listed mode comes first.
    [self performSelector:@selector(blinkeredRevealContent)
               withObject:nil
               afterDelay:blinkeredContentRevealSafetyTimeout
                  inModes:@[NSRunLoopCommonModes, NSModalPanelRunLoopMode, NSEventTrackingRunLoopMode]];
}

- (void) blinkeredRevealContent
{
    if (!_blinkeredContentHeld) {
        return;
    }
    _blinkeredContentHeld = NO;
    // P1 Bug-A: content is now actually shown — the correct moment to run the reveal paint check
    // (SEBController observes this). NOT performAfterStartActions, which fires during the hold-black.
    [[NSNotificationCenter defaultCenter] postNotificationName:@"BlinkeredContentRevealed" object:self];
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(blinkeredRevealContent) object:nil];
    // Settle the window frame BEFORE revealing: at open time the screen's usable
    // frame can still reflect the pre-kiosk state (system menu bar/Dock not yet
    // hidden), so the window could open ~28px low and visibly snap up when the
    // later reinforce pass recalculated it — the whole window (and with it the
    // home page's tab bar) jumped after content was already showing. Recalculate
    // now, while the window is still black; if geometry is already right this is
    // a no-op.
    [self setCalculatedFrame];
    // Install BEFORE the hold overlay comes off, so there is never a frame in which the empty
    // webview is on screen. Both views are opaque and cover the same rect.
    [self blinkeredInstallEmptyContentBackdropIfNeeded];
    [_blinkeredHoldOverlay removeFromSuperview];
    _blinkeredHoldOverlay = nil;
    DDLogInfo(@"Blinkered: revealing browser window content (first paint or fallback)");
}


// STAGE 3 causes 2 and 3 — "is there a document in the main frame?", asked WITHOUT believing a URL.
//
// Every defect in this workstream has been the same wrong assumption about WKWebView.URL during a
// provisional load, in alternating directions: §1.1 read it as nil when content existed; Stage 2
// read it as non-empty when content did not. **WKWebView.URL answers "what is being LOADED", never
// "what is on screen."** It is set the moment a provisional load starts — and on the failure path
// that start is the SAME event that dismisses the offline panel and releases the reveal, so the
// shipped install test said "content exists" in precisely the situation the backdrop exists for.
// The backdrop was structurally unable to install. Three rig runs, zero backdrop lines.
//
// The only trustworthy "content exists" signal is a COMMIT. Signal 1 is our own commit forward
// (_blinkeredContentCommitted). Signal 2 must be independent of that forward — the two-signal
// design exists so one broken forward cannot drop a curtain over a working lock page — so it reads
// WebKit's own bookkeeping instead: the back-forward list, which takes an item when a navigation
// commits and not when one starts.
//
// WHAT SIGNAL 2 ACTUALLY MEANS, stated narrowly (Stage 3 review A3). We clear that list ourselves:
// -[SEBAbstractWebView sebWebViewDidStartLoad] calls clearBackForwardList whenever
// allowBrowsingBackForward is NO (SEBAbstractWebView.m:941-943), which a lock session is, and that
// call is reached from didStartProvisionalNavigation. So `currentItem != nil` does not mean "a
// document has ever committed" — it means "a document is committed AND no navigation is currently
// in flight". Narrower than "WebKit's commit record", and the narrowing only ever produces Absent
// during a load that has not committed, which is the safe direction at both call sites below.
// (The clearing runs through the private `_removeAllItems` SPI, SEBOSXWKWebViewController.swift:222
// — pre-existing, but this feature now depends on that list's contents, so it is in the set.)
//
// WHAT IS STILL NOT CONFIRMED, and what that costs. Whether the list carries an item at commit time
// on the affected device is a rig question, not a review question. The Stage 3 review ruled — and
// this is recorded here rather than re-derived — that the earlier "it can only be inert" claim was
// HALF right, and the wrong half matters: in the state this feature exists for, signal 1 is NO by
// construction, so signal 2 alone decides. The arrangement guarantees the fix cannot HURT; it does
// not guarantee it WORKS.
//   * assumption too weak (no item after a genuine commit): the installer is still covered by
//     signal 1, but the re-check below becomes a permanent no-op — a safety net silently deleted.
//   * assumption too strong (an item without a commit): the curtain is suppressed in exactly the
//     failure state and Stage 2's inertness is reproduced with a new cause.
// Only the two DDLog lines can settle which. They are read in that order in the rig runbook.
typedef NS_ENUM(NSInteger, BlinkeredCommittedDocumentSignal) {
    BlinkeredCommittedDocumentUnknown = 0,   // could not inspect — the harmful answer DIFFERS per site
    BlinkeredCommittedDocumentAbsent,        // positively established: nothing has committed
    BlinkeredCommittedDocumentPresent,       // positively established: a document committed
};

// F5 — never CONSTRUCT a webview to answer a question about one.
//
// The obvious route is -[SEBAbstractWebView nativeWebView], and it is a trap: it forwards to
// SEBOSXWKWebViewController's lazy `sebWebView` accessor, which ALLOCATES a new SEBOSXWKWebView when
// _sebWebView is nil (i.e. after closeWKWebView) and force-unwraps `webViewConfiguration!` — nil once
// the weak navigationDelegate has gone, which is a crash. That is tolerable for the existing callers,
// which are user-driven; it is not tolerable here, where the re-check runs on a REPEATING TIMER in a
// locked kiosk on a child's machine.
//
// So read the view hierarchy instead — the webview this window is actually displaying. It constructs
// nothing, and it asks a better question than the delegate chain answers: if no webview is on screen
// in this window, there is also nothing drawing the white rectangle this whole feature exists to
// cover. (The white screen of 18 Aug WAS an empty WKWebView on screen, so in the state that matters
// this always finds one.)
- (WKWebView *) blinkeredDisplayedWebView
{
    return [SEBBrowserWindow blinkeredWebViewInViewTree:self.contentView];
}

+ (WKWebView *) blinkeredWebViewInViewTree:(NSView *)view
{
    if ([view isKindOfClass:[WKWebView class]]) {
        return (WKWebView *)view;
    }
    for (NSView *subview in view.subviews) {
        WKWebView *found = [self blinkeredWebViewInViewTree:subview];
        if (found) {
            return found;
        }
    }
    return nil;
}

- (BlinkeredCommittedDocumentSignal) blinkeredCommittedDocumentSignal
{
    WKWebView *displayed = [self blinkeredDisplayedWebView];
    if (!displayed) { return BlinkeredCommittedDocumentUnknown; }
    if (displayed.backForwardList.currentItem == nil) { return BlinkeredCommittedDocumentAbsent; }
    return BlinkeredCommittedDocumentPresent;
}

- (NSString *) blinkeredCommittedDocumentSignalDescription
{
    switch ([self blinkeredCommittedDocumentSignal]) {
        case BlinkeredCommittedDocumentPresent: return @"present";
        case BlinkeredCommittedDocumentAbsent:  return @"absent";
        default:                                return @"unknown";
    }
}

// TWO predicates, not one, because the safe direction is OPPOSITE at the two call sites and a single
// "has content" BOOL presents as one invariant what is really two (Stage 3 review A1).
//
//  * INSTALLER — a true answer SUPPRESSES the curtain. Unknown must read as CONTENT: a curtain over
//    a working lock page is worse than the white screen it replaces, and cannot be argued away.
- (BOOL) blinkeredWebViewMayHoldContent
{
    return [self blinkeredCommittedDocumentSignal] != BlinkeredCommittedDocumentAbsent;
}

//  * RE-CHECK — a true answer DROPS the curtain, i.e. uncovers the webview. Here Unknown is the
//    harmful answer: uncovering an empty webview IS the white screen. So only a positively
//    established PRESENCE may drop it. Previously both sites shared one predicate and the fail-safe
//    held at this one only by accident — the lazy accessor happened to reconstruct a webview rather
//    than return nil. Fixing F5 removed that accident, so the direction is now stated in code.
- (BOOL) blinkeredWebViewDefinitelyHoldsCommittedDocument
{
    return [self blinkeredCommittedDocumentSignal] == BlinkeredCommittedDocumentPresent;
}


// §5 (review F7). The reveal above hands the screen to the webview on first paint OR after
// blinkeredContentRevealSafetyTimeout. On 18 Aug that timeout fired 15.059 s after launch over a
// webview whose start load had failed PROVISIONALLY — and an empty WKWebView draws opaque WHITE.
// The parent's "the Mac is broken" was manufactured by this reveal, not by the network failure:
// the brand backdrop had been on screen the whole time and the app threw it away on a timer.
//
// So the reveal still happens exactly as before — _blinkeredContentHeld goes NO, the reveal
// notification fires, the paint detector and the whole wake-edge path arm on schedule. What
// changes is only what is UNDERNEATH: when there is nothing to show, a separate standing backdrop
// takes the screen instead of white. It is the same surface the hold was already displaying, so
// the 15-second mark becomes a non-event to look at rather than a transition to white.
//
// TWO independent signals must BOTH say "empty", and the default is to reveal. A curtain over a
// WORKING lock page is a worse outage than a white one — it looks identical to the parent and it
// cannot be argued away — so if either signal says content exists, no backdrop goes up.
- (void) blinkeredInstallEmptyContentBackdropIfNeeded
{
    if (_blinkeredEmptyContentBackdrop) return;
    // The on-device observation STAGE 3 requires: what did each signal actually say at the reveal,
    // and what was the URL saying at the same instant? One line per launch, and it is the line that
    // shows a rig run whether the back-forward list behaves as the fix assumes. Deliberately ahead
    // of the returns so it is emitted on the happy path too — a run with no backdrop and no line
    // would be indistinguishable from Stage 2's inert build, which is the confusion that cost 3.6.195.
    DDLogInfo(@"Blinkered: backdrop decision at reveal — committed=%@ backForward=%@ url=%@",
              _blinkeredContentCommitted ? @"YES" : @"NO",
              [self blinkeredCommittedDocumentSignalDescription],
              self.webView.url.absoluteString.length ? self.webView.url.absoluteString : @"(empty)");
    if (_blinkeredContentCommitted) return;                    // signal 1: our own commit forward
    // STAGE 3 cause 2. This WAS `self.webView.url.absoluteString.length > 0`, read as "the frame
    // holds a document". It never meant that: WKWebView.URL is the PROVISIONAL url from the moment
    // a load starts, so pressing Retry set it, and pressing Retry is also what released the reveal.
    // The two could not be separated in time, and the backdrop never once installed on the device.
    if ([self blinkeredWebViewMayHoldContent]) return;          // signal 2: unknown reads as CONTENT
    // WHICH sessions get a backdrop, and what it may honestly say. There are THREE Blinkered
    // session shapes, not two — the first Stage 2 report said "class and exam" and missed Focus.
    //
    //  home lock   /seb-sethomesession in the start URL, home_session.json written. A HARD lock:
    //              the kid cannot end it. Gets the brand backdrop with no exit line, because the
    //              OFFLINE PANEL names the way out and this screen faces the kid too.
    //  Focus       /home/<id>/focus-content. The server routes it around /seb-sethomesession on
    //              purpose, so BOTH halves of the home predicate are false — and the offline panel
    //              keys on the same session file, so it is absent here as well. Without this
    //              branch a Focus session on a dead network reproduces 18 Aug verbatim, on a
    //              family surface, with NOTHING on screen naming the way out. Its own wording:
    //              "Locked by Blinkered" would be a lie (Focus ships allowQuit with no quit
    //              password, so Cmd+Q ends it), and since there is no panel here this backdrop is
    //              what must carry the exit line — the exception review F8/C9 explicitly allows.
    //  class/exam  neither matches. Untouched: they hold PURE BLACK and reveal to SEB's own Load
    //              Error alert, which is designed behaviour and not this plan's to change.
    BOOL homeLock = [SEBBrowserWindow blinkeredIsHomeLockSession]
        || [self.browserController.sebController blinkeredHomeSessionInfo] != nil;
    BOOL focusSession = !homeLock && [SEBBrowserWindow blinkeredIsFocusSession];
    BOOL backdropSession = homeLock || focusSession;
    if (!backdropSession) return;
    NSView *backdrop = [[NSView alloc] initWithFrame:self.contentView.bounds];
    backdrop.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    if (focusSession) {
        // Never promise an exit we cannot honour: read the quit password at RUNTIME rather than
        // trusting the server's allowQuit — the same test the offline panel uses for its own
        // wording. "Can't reach Blinkered right now" is true for exactly as long as this view is
        // up, because it comes down the moment a document commits.
        NSString *quitHash = [[NSUserDefaults standardUserDefaults] secureObjectForKey:@"org_safeexambrowser_SEB_hashedQuitPassword"];
        [SEBBrowserWindow blinkeredAddBrandBackdropContentToView:backdrop
                                                           title:NSLocalizedString(@"Focus session", @"")
                                                          detail:(quitHash.length == 0
                                                                  ? NSLocalizedString(@"Can’t reach Blinkered right now. Press ⌘Q to end this session.", @"")
                                                                  : NSLocalizedString(@"Can’t reach Blinkered right now.", @""))];
    } else {
        [SEBBrowserWindow blinkeredAddBrandBackdropContentToView:backdrop];
    }
    [self.contentView addSubview:backdrop positioned:NSWindowAbove relativeTo:nil];
    _blinkeredEmptyContentBackdrop = backdrop;
    // C9: this sits BEHIND the offline panel, structurally — the panel is a separate alert window
    // raised above the lockdown covers, and this is a subview of the browser window's content
    // view. It must never replace the panel: the panel is the only surface that NAMES the way out.
    DDLogWarn(@"Blinkered: reveal reached an empty webview — holding the brand backdrop instead of uncovering white (%@)",
              focusSession ? @"focus session" : @"home lock");
}


// C7′ — the moment real content lands, the curtain comes down. A recovered device must not be left
// behind it, and "recovered" is COMMIT, not finish: a page with one hung subresource never
// finishes, and it is already painting long before it would.
- (void) blinkeredDropEmptyContentBackdrop
{
    if (!_blinkeredEmptyContentBackdrop) return;
    [_blinkeredEmptyContentBackdrop removeFromSuperview];
    _blinkeredEmptyContentBackdrop = nil;
    DDLogInfo(@"Blinkered: content committed — empty-content backdrop removed");
}


// C4 (review R6.3). The installer decides ONCE, at reveal, and nothing re-decides — so any failure
// of the removal path is permanent, and because this view sits above the content view it also
// swallows every mouse event over the window. A cheap re-read on the paint timer closes that
// without suppressing anything: it is a plain observation, it changes no flag the recovery paths
// consult, and it cannot fire on a device that has nothing to show.
//
// NOTE (STAGE 3): the paint timer that drives this is a plain scheduledTimer, i.e. default mode, so
// it too is starved while the offline panel is modal. That is left alone deliberately — it is a
// FALLBACK for a broken commit forward, the primary drop path is -sebWebViewDidCommitLoad, and
// widening that timer's modes would change the cadence of the paint detector as well.
//
// It drops the backdrop only when real content is PRESENT. It must never drop on elapsed time —
// a blind timeout uncovers the empty webview and paints white again, which is the bug.
- (void) blinkeredRecheckEmptyContentBackdrop
{
    if (!_blinkeredEmptyContentBackdrop) return;
    // STAGE 3 cause 3 — the same wrong signal, inverted. Reading url.absoluteString here would tear
    // the curtain down the moment ANY provisional load started, i.e. the instant the parent pressed
    // Retry, repainting white mid-recovery — replacing cause 1 with a new one. It must be the same
    // commit-derived test as the installer, so the curtain comes down for a document and not for an
    // intention.
    if (![self blinkeredWebViewDefinitelyHoldsCommittedDocument]) return;  // unknown STAYS UP here
    DDLogWarn(@"Blinkered: content is present but the empty-content backdrop was still up — dropping it (the commit/finish removal path did not fire)");
    _blinkeredContentCommitted = YES;
    [self blinkeredDropEmptyContentBackdrop];
}


- (void)sebWebViewDidCommitLoad
{
    _blinkeredContentCommitted = YES;
    // STAGE 3: the one line that CONFIRMS, on the device, the semantics signal 2 rests on — does the
    // back-forward list carry an item at commit time? The plan forbids assuming it, and this is
    // cheap (one commit per navigation). "present" here proves the fallback works; "absent" proves
    // only that the fallback is inert, never that a working page can be curtained.
    // The window is named because this forward fires for EVERY SEBBrowserWindow, site windows
    // included (review F9) — a rig runner must not read a site window's answer as the main frame's.
    DDLogInfo(@"Blinkered: didCommit — backForward=%@ (%@)",
              [self blinkeredCommittedDocumentSignalDescription],
              self.isMainBrowserWindow ? @"main window" : @"site window");
    [self blinkeredDropEmptyContentBackdrop];
}

- (void)sebWebViewDidFinishLoad
{
    [self setLoading:NO];
    // Belt and braces behind the commit hook: a finish implies a commit, so if the commit forward
    // ever breaks, the curtain still comes down on a page that loaded.
    _blinkeredContentCommitted = YES;
    [self blinkeredDropEmptyContentBackdrop];
    // Reveal before the splash is asked to close, so the splash never closes onto
    // a black window.
    [self blinkeredRevealContent];
    [self.browserWindowController sebWebViewDidFinishLoad];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:@"requestCloseAboutWindowNotification" object:self];
    });
}

- (void)sebWebViewDidFailLoadWithError:(NSError *)error
{
    // Don't display the errors 102 "Frame load interrupted", this can be caused by
    // the URL filter canceling loading a blocked URL,
    // and 204 "Plug-in handled load"
    if (error.code != 102 && error.code != 204 && !(self.browserController.directConfigDownloadAttempted)) {
        // A real failed load must never leave the held window black — the error
        // alert and whatever the page shows behind it have to be visible. (The
        // filtered benign codes above must NOT reveal: the page is still loading.)
        [self blinkeredRevealContent];
        NSString *failingURLString = [error.userInfo objectForKey:NSURLErrorFailingURLStringErrorKey];
        NSString *errorMessage = error.localizedDescription;
        DDLogError(@"%s: Load error with localized description: %@", __FUNCTION__, errorMessage);
        
        //Close the About Window first, because it would hide the error alert
        [[NSNotificationCenter defaultCenter] postNotificationName:@"requestCloseAboutWindowNotification" object:self];
        
        NSString *titleString = NSLocalizedString(@"Load Error",nil);
        [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
        [self makeKeyAndOrderFront:self];
        
        NSAlert *modalAlert = [self.browserController.sebController newAlert];
        [modalAlert setMessageText:titleString];
        [modalAlert setInformativeText:errorMessage];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"Retry", @"")];
        [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
        [modalAlert setAlertStyle:NSAlertStyleCritical];
        void (^alertOKHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
            [self.browserController.sebController removeAlertWindow:modalAlert.window];
            switch(answer) {
                case NSAlertFirstButtonReturn:
                {
                    //Retry: try reloading
                    //self.browserController.currentMainHost = nil;
                    DDLogInfo(@"Trying to reload after %s: %@, localized error: %@", __FUNCTION__, error.description, errorMessage);
                    NSURL *failingURL = [NSURL URLWithString:failingURLString];
                    if (failingURL && ![[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_browserConnectionErrorReload"]) {
                        [self.browserControllerDelegate loadURL:failingURL];
                    } else {
                        [self.browserControllerDelegate reload];
                    }
                    return;
                }
                default:
                    DDLogError(@"Alert was dismissed by the system with NSModalResponse %ld.", (long)answer);
                case NSAlertSecondButtonReturn:
                    // Close a temporary browser window which might have been opened for loading a config file from a SEB URL
                    DDLogInfo(@"User didn't select to reload after %s: %@, localized error: %@", __FUNCTION__, error.description, errorMessage);
                    [self.browserController openingConfigURLFailed];
                    return;
            }
        };
        [self.browserController.sebController runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))alertOKHandler];
    }
}

- (void)sebWebViewDidUpdateTitle:(nullable NSString *)title
{
    title = [self.browserController webPageTitle:title orURL:self.webView.url mainWebView:self.webView.isMainBrowserWebView];
    [self.browserController setTitle: title forWindow:self withWebView:self.webView];
    // Blinkered: show just the page (site) name in the window title — no "Blinkered <version>"
    // prefix, which looked odd to families and exposed the build number.
    [self setTitle:title ?: @""];
}

- (void)webView:(WKWebView *)webView
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    if (_browserController == nil) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    } else {
        [self.browserController webView:webView didReceiveAuthenticationChallenge:challenge completionHandler:completionHandler];
    }
}

- (void)webView:(WKWebView *)webView
runJavaScriptAlertPanelWithMessage:(NSString *)message
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(void))completionHandler
{
    NSString *pageTitle = webView.title;
    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    [self makeKeyAndOrderFront:self];
    
    NSAlert *modalAlert = [self.browserController.sebController newAlert];
    DDLogWarn(@"%s: %@", __FUNCTION__, message);
    [modalAlert setMessageText:pageTitle];
    [modalAlert setInformativeText:message];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
    [modalAlert setAlertStyle:NSAlertStyleInformational];
    void (^alertOKHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
        [self.browserController.sebController removeAlertWindow:modalAlert.window];
        completionHandler();
    };
    [self.browserController.sebController runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))alertOKHandler];
}


- (void)pageTitle:(NSString *)pageTitle
runJavaScriptAlertPanelWithMessage:(NSString *)message
{
    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    [self makeKeyAndOrderFront:self];
    
    NSAlert *modalAlert = [self.browserController.sebController newAlert];
    DDLogWarn(@"%s: %@", __FUNCTION__, message);
    [modalAlert setMessageText:pageTitle];
    [modalAlert setInformativeText:message];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
    [modalAlert setAlertStyle:NSAlertStyleInformational];
    void (^alertOKHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
        [self.browserController.sebController removeAlertWindow:modalAlert.window];
    };
    [self.browserController.sebController runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))alertOKHandler];
}


- (void)webView:(WKWebView *)webView
runJavaScriptConfirmPanelWithMessage:(NSString *)message
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(BOOL result))completionHandler
{
    NSString *pageTitle = webView.title;
    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    [self makeKeyAndOrderFront:self];
    
    NSModalResponse alertResultButton;
    if (@available(macOS 12.0, *)) {
    } else {
        if (@available(macOS 11.0, *)) {
            if (self.browserController.sebController.isAACEnabled || self.browserController.sebController.wasAACEnabled) {
                alertResultButton = [self showCustomModalAlert:[NSString stringWithFormat:@"%@\n\n%@", pageTitle, message]];
                completionHandler(YES);
            }
        }
    }
    NSAlert *modalAlert = [self.browserController.sebController newAlert];
    DDLogInfo(@"%s: %@", __FUNCTION__, message);
    [modalAlert setMessageText:pageTitle];
    [modalAlert setInformativeText:message];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
    [modalAlert setAlertStyle:NSAlertStyleInformational];
    alertResultButton = [modalAlert runModal];
    
    [self.browserController.sebController removeAlertWindow:modalAlert.window];
    completionHandler(alertResultButton == NSAlertFirstButtonReturn);
}


- (BOOL)pageTitle:(NSString *)pageTitle
runJavaScriptConfirmPanelWithMessage:(NSString *)message
{
    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    [self makeKeyAndOrderFront:self];
    
    NSModalResponse alertResultButton;
    if (@available(macOS 12.0, *)) {
    } else {
        if (@available(macOS 11.0, *)) {
            if (self.browserController.sebController.isAACEnabled || self.browserController.sebController.wasAACEnabled) {
                alertResultButton = [self showCustomModalAlert:[NSString stringWithFormat:@"%@\n\n%@", pageTitle, message]];
                return alertResultButton == NSAlertFirstButtonReturn;
            }
        }
    }
    NSAlert *modalAlert = [self.browserController.sebController newAlert];
    DDLogInfo(@"%s: %@", __FUNCTION__, message);
    [modalAlert setMessageText:pageTitle];
    [modalAlert setInformativeText:message];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
    [modalAlert addButtonWithTitle:NSLocalizedString(@"Cancel", @"")];
    [modalAlert setAlertStyle:NSAlertStyleInformational];
    alertResultButton = [modalAlert runModal];
    
    [self.browserController.sebController removeAlertWindow:modalAlert.window];
    return alertResultButton == NSAlertFirstButtonReturn;
}


- (IBAction) customAlertOKButton: (id)sender {
    [NSApp stopModalWithCode:NSAlertFirstButtonReturn];
}


- (IBAction) customAlertCancelButton: (id)sender {
    [NSApp stopModalWithCode:NSAlertSecondButtonReturn];
}


- (NSModalResponse) showCustomModalAlert:(NSString *)text
{
    self.customAlertText.stringValue = text;
    [NSApp beginSheet: self.customAlert
       modalForWindow: self
        modalDelegate: nil
       didEndSelector: nil
          contextInfo: nil];
    NSModalResponse answer = [NSApp runModalForWindow: self];
    [NSApp endSheet: self.customAlert];
    [NSApp abortModal];
    [self.customAlert orderOut: self];
    return answer;
}


- (void)webView:(WKWebView *)webView
runJavaScriptTextInputPanelWithPrompt:(NSString *)prompt
    defaultText:(nullable NSString *)defaultText
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(NSString *result))completionHandler
{
    [self.browserController webView:webView runJavaScriptTextInputPanelWithPrompt:prompt defaultText:defaultText initiatedByFrame:frame completionHandler:completionHandler];
}


- (NSString *)pageTitle:(NSString *)pageTitle
runJavaScriptTextInputPanelWithPrompt:(NSString *)prompt
            defaultText:(NSString *)defaultText
{
    return [self.browserController pageTitle:pageTitle runJavaScriptTextInputPanelWithPrompt:prompt defaultText:defaultText];
}


- (void)webView:(WKWebView *)webView
runOpenPanelWithParameters:(id)parameters
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(NSArray<NSURL *> *URLs))completionHandler
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if (self.allowUploads) {
        if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_chooseFileToUploadPolicy"] != manuallyWithFileRequester) {
            // If the policy isn't "manually with file requester"
            // We try to choose the filename and path ourselves, it's the last dowloaded file
            NSInteger lastDownloadPathIndex = [[MyGlobals sharedMyGlobals] lastDownloadPath];
            NSMutableArray *downloadPaths = [[MyGlobals sharedMyGlobals] downloadPath];
            if (downloadPaths && downloadPaths.count) {
                if (lastDownloadPathIndex == -1) {
                    //if the index counter of the last downloaded file is -1, we have reached the beginning of the list of downloaded files
                    lastDownloadPathIndex = [downloadPaths count]-1; //so we jump to the last path in the list
                }
                NSString *lastDownloadPath = [downloadPaths objectAtIndex:lastDownloadPathIndex];
                lastDownloadPathIndex--;
                [[MyGlobals sharedMyGlobals] setLastDownloadPath:lastDownloadPathIndex];
                if (lastDownloadPath && [[NSFileManager defaultManager] fileExistsAtPath:lastDownloadPath]) {
                    completionHandler(@[[NSURL fileURLWithPath:lastDownloadPath]]);
                    [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
                    [self makeKeyAndOrderFront:self];
                    
                    NSAlert *modalAlert = [self.browserController.sebController newAlert];
                    DDLogInfo(@"File to upload automatically chosen");
                    [modalAlert setMessageText:NSLocalizedString(@"File Automatically Chosen", @"")];
                    [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"%@ will upload the same file which was downloaded before. If you edited it in a third party application, be sure you have saved it with the same name at the same path.", @""), SEBShortAppName]];
                    [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                    [modalAlert setAlertStyle:NSAlertStyleInformational];
                    void (^alertOKHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                        [self.browserController.sebController removeAlertWindow:modalAlert.window];
                    };
                    [self.browserController.sebController runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))alertOKHandler];
                    return;
                }
            }
            
            if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_chooseFileToUploadPolicy"] == onlyAllowUploadSameFileDownloadedBefore) {
                // if the policy is "Only allow to upload the same file downloaded before"
                [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
                [self makeKeyAndOrderFront:self];
                
                NSAlert *modalAlert = [self.browserController.sebController newAlert];
                DDLogError(@"File to upload (which was downloaded before) not found");
                [modalAlert setMessageText:NSLocalizedString(@"File to Upload Not Found!", @"")];
                [modalAlert setInformativeText:[NSString stringWithFormat:NSLocalizedString(@"%@ is configured to only allow uploading a file which was downloaded before. So download a file and if you edit it in a third party application, be sure to save it with the same name at the same path.", @""), SEBShortAppName]];
                [modalAlert addButtonWithTitle:NSLocalizedString(@"OK", @"")];
                [modalAlert setAlertStyle:NSAlertStyleCritical];
                void (^alertOKHandler)(NSModalResponse) = ^void (NSModalResponse answer) {
                    [self.browserController.sebController removeAlertWindow:modalAlert.window];
                };
                completionHandler(nil);
                [self.browserController.sebController runModalAlert:modalAlert conditionallyForWindow:self.browserController.mainBrowserWindow completionHandler:(void (^)(NSModalResponse answer))alertOKHandler];
                return;
            }
        }
        // Create the File Open Dialog class.
        NSOpenPanel* openFilePanel = [NSOpenPanel openPanel];
        
        // Enable the selection of files in the dialog.
        openFilePanel.canChooseFiles = YES;
        
        if (@available(macOS 10.12, *)) {
            if ([[parameters class] isEqual:WKOpenPanelParameters.class]) {
                // Is selection of multiple files at a time allowed?
                openFilePanel.allowsMultipleSelection = ((WKOpenPanelParameters *)parameters).allowsMultipleSelection;
                // Is selection of directories allowed?
                if (@available(macOS 10.13.4, *)) {
                    openFilePanel.canChooseDirectories = ((WKOpenPanelParameters *)parameters).allowsDirectories;
                } else {
                    openFilePanel.canChooseDirectories = NO;
                }
            }
        }
        if ([parameters respondsToSelector: @selector(boolValue)]) {
            openFilePanel.allowsMultipleSelection = ((NSNumber *)parameters).boolValue;
            openFilePanel.canChooseDirectories = NO;
        }
        
        // Change text of the open button in file dialog
        openFilePanel.prompt = NSLocalizedString(@"Choose",nil);
        
        // Change default directory in file dialog
        openFilePanel.directoryURL = [self.browserController downloadDirectoryURL];
        
        [[NSRunningApplication currentApplication] activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
        [self makeKeyAndOrderFront:self];
        
        // Display the dialog.  If the OK button was pressed,
        // process the files.
        [openFilePanel beginSheetModalForWindow:self
                              completionHandler:^(NSInteger result) {
            if (result == NSModalResponseOK) {
                // Get an array containing the full filenames of all
                // files and directories selected.
                NSArray* fileURLs = [openFilePanel URLs];
                completionHandler(fileURLs);
            } else {
                completionHandler(nil);
            }
        }];
    } else {
        completionHandler(nil);
        [self.browserController showAlertNotAllowedDownUploading:YES];
    }
}


- (void) shouldStartLoadFormSubmittedURL:(NSURL *)url
{
    [self.browserController shouldStartLoadFormSubmittedURL:url];
}


- (void) transferCookiesToWKWebViewWithCompletionHandler:(void (^)(void))completionHandler
{
    [self.browserController transferCookiesToWKWebViewWithCompletionHandler:completionHandler];
}


- (BOOL) showURLFilterAlertForRequest:(NSURLRequest *)request
                     forContentFilter:(BOOL)contentFilter
                       filterResponse:(URLFilterRuleActions)filterResponse
{
    return [self showURLFilterAlertSheetForWindow:self forRequest:request forContentFilter:contentFilter filterResponse:filterResponse];
}


- (NSURL *) downloadPathURL
{
    return self.browserController.downloadPathURL;
}


- (void) downloadFileFromURL:(NSURL *)url filename:(NSString *)filename cookies:(NSArray <NSHTTPCookie *>*)cookies
{
    [self.browserController downloadFileFromURL:url filename:filename cookies:cookies sender:self];
}


- (void) fileDownloadedSuccessfully:(NSString *)path
{
    [self.browserController fileDownloadedSuccessfully:path];
}


- (void) conditionallyDownloadAndOpenSEBConfigFromURL:(NSURL *)url
{
    [self.browserController openConfigFromSEBURL:url];
}


- (void) openSEBConfigFromData:(NSData *)sebConfigData;
{
    [self.browserController.sebController storeNewSEBSettingsFromData:sebConfigData];
}


- (void) downloadSEBConfigFileFromURL:(NSURL *)url originalURL:(NSURL *)originalURL cookies:(NSArray <NSHTTPCookie *>*)cookies
{
    [self.browserController downloadSEBConfigFileFromURL:url originalURL:originalURL cookies:cookies sender:self];
}


- (BOOL) downloadingInTemporaryWebView
{
    return [self.browserController downloadingInTemporaryWebView];
}


@end

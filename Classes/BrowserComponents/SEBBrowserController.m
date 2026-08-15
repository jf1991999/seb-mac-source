//
//  SEBBrowserController.m
//  SafeExamBrowser
//
//  Created by Daniel R. Schneider on 22/01/16.
//  Copyright (c) 2010-2025 Daniel R. Schneider, ETH Zurich, IT Services,
//  based on the original idea of Safe Exam Browser
//  by Stefan Schneider, University of Giessen
//  Project concept: Thomas Piendl, Daniel R. Schneider, Damian Buechel,
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
//  Contributor(s): dmcd, Copyright (c) 2015-2016 Janison
//

#import "SEBBrowserController.h"
#import "SEBController.h"   // BlinkeredTeardownStarted() — dedupe of the page's bridge-quit + /seb-quit pair
#import "SEBURLFilter.h"
#import "CustomHTTPProtocol.h"

// Disable ITP (Intelligent Tracking Prevention) via private WebKit API.
// Blinkered is a controlled classroom browser — cross-site cookie restrictions
// break legitimate login flows across different starting domains.
//
// macOS 26 removed _setResourceLoadStatisticsEnabled: from WKWebsiteDataStore.
// The replacement is _WKPreferencesSetStorageBlockingPolicy(prefs, 0 = AllowAll).
// We call both: the policy call works on macOS 26+, the data-store call on older macOS.
@interface WKWebsiteDataStore (BlinkeredITP)
- (void)_setResourceLoadStatisticsEnabled:(BOOL)enabled;
// Records a first-party "user interaction" for a domain so ITP trusts it from
// the first iframe load, without needing a prior popup/full-window visit.
- (void)_statisticsSetHasHadUserInteraction:(NSString *)hostName value:(BOOL)value completionHandler:(void (^)(void))completionHandler;
@end

// _WKPreferencesSetStorageBlockingPolicy is a private WebKit symbol not present in the
// SDK's stub (.tbd) file, so we must resolve it at runtime via dlsym.
// _WKStorageBlockingPolicyAllowAll = 0 (no cookie/storage restrictions)
#include <dlfcn.h>
typedef void (*_WKPreferencesSetStorageBlockingPolicyFn)(void *prefs, uint32_t policy);
#import "SEBCertServices.h"
#include "x509_crt.h"
#import "NSURL+SEBURL.h"
#import "SEBCryptor.h"
#import "dirent.h"
#import "SafeExamBrowser-Swift.h"

void mbedtls_x509_private_seb_obtainLastPublicKeyASN1Block(unsigned char **block, unsigned int *len);

static NSString * const authenticationHost = @"host";
static NSString * const authenticationUsername = @"username";
static NSString * const authenticationPassword = @"password";

@interface SEBBrowserController () <CustomHTTPProtocolDelegate> {
    NSMutableArray *authorizedHosts;
    NSMutableArray *previousAuthentications;
}

@property (nonatomic, strong) CustomHTTPProtocol *authenticatingProtocol;
@property (nonatomic, strong) NSString *lastUsername;

// Blinkered: per-child cookie isolation on shared devices (see profileSwitch handler).
- (void)blinkeredProfileSwitch:(NSString *)action childId:(NSString *)childId url:(NSString *)navUrl webView:(WKWebView *)webView;
- (void)blinkeredSaveCookies:(NSArray<NSHTTPCookie *> *)cookies forChild:(NSString *)childId;
- (NSArray<NSHTTPCookie *> *)blinkeredLoadCookiesForChild:(NSString *)childId;
- (NSString *)blinkeredCookiePathForChild:(NSString *)childId;
// Legacy GLOBAL cookie jar (appSupport/Blinkered/cookies.json) — read for the one-time migration into an
// assigned kid's per-child jar, then deleted.
- (NSArray<NSHTTPCookie *> *)blinkeredLoadGlobalCookies;
- (void)blinkeredDeleteGlobalCookieFile;
// Which child the persistent cookie store currently belongs to (a small file). Used to WIPE on a kid-change
// so a new kid never inherits the previous kid's residual cookies (the shared-device leak).
- (NSString *)blinkeredReadCookieStoreOwner;
- (void)blinkeredWriteCookieStoreOwner:(NSString *)childId;

// Blinkered: the ONE window-resolution rule shared by every home-tab-bar verb
// (focusWindow / reloadWindow / navigateWindow) — see the method comment. Main thread only.
- (NSWindow *)blinkeredTabTargetWindowForURL:(NSString *)tabUrl
                                  mainWindow:(NSWindow *)mainWin
                                  allWindows:(NSArray *)allWindows
                              orderedWindows:(NSArray *)orderedWindows
                                groupNumbers:(NSMutableSet **)outGroupNumbers;

@end

@implementation SEBBrowserController

void run_block_on_ui_thread(dispatch_block_t block)
{
    if ([NSThread isMainThread])
        block();
    else
        dispatch_sync(dispatch_get_main_queue(), block);
}

// Empties all cookies, caches and credential stores, removes disk files, flushes in-progress
// downloads to disk, and ensures that future requests occur on a new socket.
- (void)resetAllCookiesWithCompletionHandler:(void (^)(void))completionHandler
{
    [[NSURLSession sharedSession] resetWithCompletionHandler:^{
        run_block_on_ui_thread(^{
            if (@available(macOS 10.13, iOS 11.0, *)) {
                [self.wkWebViewConfiguration.websiteDataStore removeDataOfTypes:[NSSet setWithObjects:WKWebsiteDataTypeCookies, WKWebsiteDataTypeSessionStorage, WKWebsiteDataTypeDiskCache, nil] modifiedSince:NSDate.distantPast completionHandler:^{
                    DDLogInfo(@"-[SEBBrowserController resetAllCookies] Cookies, caches, credential stores and WKWebsiteDataTypes were reset");
                    completionHandler();
                }];
            } else {
                DDLogInfo(@"-[SEBBrowserController resetAllCookies] Cookies, caches and credential stores were reset");
                completionHandler();
            }
        });
    }];
}


// Initialize and register as delegate for custom URL protocol
- (instancetype)init
{
    DDLogInfo(@"-[SEBBrowserController init]");
    self = [super init];
    if (self) {
        [self initSessionSettings];
        // Get JavaScript code for modifying targets of hyperlinks in the webpage so can be open in new tabs
        NSString *path = [[NSBundle mainBundle] pathForResource:@"ModifyPages" ofType:@"js"];
        self.javaScriptFunctions = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];

        void (^initComplete)(void) = ^{
            self.finishedInitializing = YES;
            NSURL *sebURLWaitingToBeOpened = self.openConfigSEBURL;
            if (sebURLWaitingToBeOpened) {
                self.openConfigSEBURL = nil;
                [self openConfigFromSEBURL:sebURLWaitingToBeOpened];
            }
        };
        if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_examSessionClearCookiesOnStart"]) {
            DDLogInfo(@"-[SEBBrowserController init] Clearing cookies on start (examSessionClearCookiesOnStart = true)");
            [self resetAllCookiesWithCompletionHandler:initComplete];
        } else {
            DDLogInfo(@"-[SEBBrowserController init] Preserving cookies (examSessionClearCookiesOnStart = false)");
            [self transferCookiesToWKWebViewWithCompletionHandler:initComplete];
        }
    }
    return self;
}

// The trusted-origin definition lives on SEBAbstractWebView so the quit-URL interceptor there and
// this bridge gate share ONE definition (§8.14 — two of these existed once and drifted).

// [R1-1] Only our own served pages may drive the bridge. Script-message handlers are exposed to
// EVERY frame of EVERY origin in webviews sharing this configuration — so without this gate, any
// JavaScript running inside a lock (an allow-listed site with an XSS/eval sink, a kid's own
// allow-listed domain, a cross-origin iframe) could postMessage setQuitPassword and overwrite the
// quit hash — the exact offline exit boundary (OFFLINE_EXIT_CODE_PLAN.md §2.0). The check uses
// frameInfo.securityOrigin — the SENDING frame's origin, which page content cannot forge.
- (BOOL)blinkeredTrustedBridgeOrigin:(WKScriptMessage *)message
{
    WKSecurityOrigin *origin = message.frameInfo.securityOrigin;
    return [SEBAbstractWebView blinkeredTrustedOriginHost:origin.host protocol:origin.protocol];
}

// [R1-2] THROTTLE — a hard prerequisite of the allow-list gate, not a nicety.
//
// "Deduped server-side" describes the dashboard, not the device's radio: every refusal used to fire
// its own dataTaskWithRequest:. That was survivable while only two message types could reach this
// path. Under the allow-list gate below, EVERY type can, from ANY frame — so
// `for(;;) postMessage({type:'getOpenWindows'})` on a page inside a lock becomes an unbounded HTTPS
// POST flood: battery and network drain on a locked child's device, with no symptom the watchdog
// sees, because the app is still running. Closing an escape by opening a denial-of-service is not
// closing it.
//
// Three bounds, all cheap:
//   • one report per (type, origin) per BlinkeredTamperReportFloor seconds — the signal a parent
//     needs is "this happened", not "this happened 40,000 times";
//   • a cap on how many distinct keys we track, so an attacker cannot grow the map without limit by
//     iframing an endless supply of sub-domains;
//   • a whole-session cap on POSTs, as a backstop against a hole in the first two.
// A refusal is ALWAYS logged locally (DDLog, rate-limited by the same key); only the network call
// is throttled.
static const NSTimeInterval BlinkeredTamperReportFloor = 300.0;   // 5 min per (type, origin)
static const NSUInteger BlinkeredTamperKeyCap          = 64;      // distinct (type, origin) pairs
static const NSUInteger BlinkeredTamperSessionCap      = 200;     // POSTs per app session

// Returns YES at most once per floor per (type, origin), and never more than the session cap.
// Callers report only when this says so; they log locally regardless.
- (BOOL)blinkeredShouldReportTamperKey:(NSString *)key
{
    static NSMutableDictionary<NSString *, NSDate *> *lastReported;
    static NSUInteger reportsThisSession;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ lastReported = [NSMutableDictionary dictionary]; });

    @synchronized (lastReported) {
        if (reportsThisSession >= BlinkeredTamperSessionCap) {
            return NO;
        }
        NSDate *last = lastReported[key];
        if (last && [[NSDate date] timeIntervalSinceDate:last] < BlinkeredTamperReportFloor) {
            return NO;
        }
        // Evict everything once we hit the cap rather than tracking recency: this map exists to
        // suppress a flood, and a flood re-populates it in milliseconds. The only cost of a wrong
        // eviction is one extra POST, and the session cap still bounds that.
        if (!last && lastReported.count >= BlinkeredTamperKeyCap) {
            [lastReported removeAllObjects];
        }
        lastReported[key] = [NSDate date];
        reportsThisSession++;
        return YES;
    }
}

// Best-effort security event to the server (parent alert, deduped server-side) when a page is
// caught sending a bridge message from an untrusted origin. Device creds from agent.json.
// Throttled per (type, origin) — see blinkeredShouldReportTamperKey: above.
- (void)blinkeredReportBridgeTamper:(NSString *)type origin:(NSString *)origin
{
    if (![self blinkeredShouldReportTamperKey:[NSString stringWithFormat:@"%@|%@", type ?: @"?", origin ?: @"?"]]) {
        return;
    }
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *agentJson = [[[dirs firstObject] stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    NSData *credData = [NSData dataWithContentsOfFile:agentJson];
    NSDictionary *creds = credData ? [NSJSONSerialization JSONObjectWithData:credData options:0 error:nil] : nil;
    if (![creds isKindOfClass:[NSDictionary class]]) return;
    NSString *devId = creds[@"id"], *devTok = creds[@"token"];
    NSString *server = [creds[@"server"] isKindOfClass:[NSString class]] ? creds[@"server"] : @"https://blinkered.com.au";
    if (![devId isKindOfClass:[NSString class]] || ![devTok isKindOfClass:[NSString class]]) return;
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/home/devices/%@/security-event", server, devId]];
    if (!url) return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{ @"token": devTok, @"type": @"bridge_tamper" } options:0 error:nil];
    if (req.HTTPBody) [[[NSURLSession sharedSession] dataTaskWithRequest:req] resume];
}

// Blinkered: which open site window does a home-tab-bar action on `tabUrl` mean?
//
// ONE rule for every tab-bar verb — focusWindow, reloadWindow and navigateWindow all call
// this. They used to carry three separate copies of the matching logic and only focusWindow
// was taught about window groups, so ↻ and ‹ / › still resolved to the tab's ORIGINAL window:
// with a OneDrive document in front, reload refreshed the file list AND ordered it to the
// front, re-burying the document — the very "my file closed" bug the group logic fixed,
// reachable through a different button. Duplicated resolution is what allowed that drift;
// keep this the only copy.
//
// The rule, in order:
//   GROUP  — windows whose current or original URL/host matches the tab seed the group, then
//            windows OPENED BY a group member join it transitively (blinkeredOpenerWindowNumber).
//            A document opened from the OneDrive file list lives on another host entirely
//            (tab = www.onedrive.com, list = onedrive.live.com, doc = an Office host), so the
//            opener chain is the ONLY tie between a document and its tab. Host matching alone
//            can never make it — the Windows build shipped without this and did nothing useful.
//   PASS 1 — MRU: first group member in orderedWindows (front-to-back, visible only). The
//            front-most is the window the student was last using.
//   PASS 2 — revival: nothing visible matched, so scan ALL windows including hidden ones. The
//            red-close button hides additional windows (orderOut) rather than closing them, so
//            a window the user "closed" is invisible but alive and must still be found
//            (exact match preferred, then host, then any hidden group member).
//
// Returns nil only when the tab genuinely has no surviving window; the caller decides whether
// that means reopen (focusWindow/reloadWindow) or no-op (navigateWindow). There is deliberately
// no "any open window" fallback — that surfaced a DIFFERENT site's window when several were open.
//
// `outGroupNumbers` returns the resolved group for the rig diagnostic lines. Main thread only
// (it reads NSApplication's window lists). Window lists are passed in rather than read here so
// the rule can be exercised without a live NSApplication.
- (NSWindow *)blinkeredTabTargetWindowForURL:(NSString *)tabUrl
                                  mainWindow:(NSWindow *)mainWin
                                  allWindows:(NSArray *)allWindows
                              orderedWindows:(NSArray *)orderedWindows
                                groupNumbers:(NSMutableSet **)outGroupNumbers
{
    NSString *targetHost = [NSURL URLWithString:tabUrl].host ?: @"";
    // Does this window belong to the tab? Exact current/original URL, or same host (current or
    // original) — so with several 🪟 sites open, acting on one tab never hits another site's window.
    BOOL (^matchesTab)(NSWindow *) = ^BOOL(NSWindow *win) {
        if (win == mainWin) return NO;
        if (![win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) return NO;
        id abstractWebView = [win valueForKey:@"webView"];
        if (!abstractWebView) return NO;
        WKWebView *wkView = (WKWebView *)[abstractWebView performSelector:@selector(nativeWebView)];
        if (![wkView isKindOfClass:[WKWebView class]]) return NO;
        NSString *winUrl = wkView.URL.absoluteString ?: @"";
        NSString *origUrl = [win valueForKey:@"blinkeredOriginalURLString"] ?: @"";
        if ([winUrl isEqualToString:tabUrl] || [origUrl isEqualToString:tabUrl]) return YES;
        NSString *origHost = [NSURL URLWithString:origUrl].host ?: @"";
        return [[wkView.URL host] isEqualToString:targetHost] ||
               (targetHost.length && [origHost isEqualToString:targetHost]);
    };
    NSMutableSet *groupNumbers = [NSMutableSet set];
    for (NSWindow *win in allWindows) {
        if (matchesTab(win)) [groupNumbers addObject:@(win.windowNumber)];
    }
    BOOL grew = YES;
    while (grew) {
        grew = NO;
        for (NSWindow *win in allWindows) {
            if (win == mainWin) continue;
            if (![win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) continue;
            if ([groupNumbers containsObject:@(win.windowNumber)]) continue;
            NSNumber *opener = [win valueForKey:@"blinkeredOpenerWindowNumber"];
            if (opener.integerValue > 0 && [groupNumbers containsObject:opener]) {
                [groupNumbers addObject:@(win.windowNumber)];
                grew = YES;
            }
        }
    }
    if (outGroupNumbers) *outGroupNumbers = groupNumbers;
    // PASS 1 — MRU.
    for (NSWindow *win in orderedWindows) {
        if (win == mainWin) continue;
        if (![win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) continue;
        if ([groupNumbers containsObject:@(win.windowNumber)]) return win;
    }
    // PASS 2 — revival.
    NSWindow *exactMatch = nil;
    NSWindow *hostMatch  = nil;
    NSWindow *groupMatch = nil;
    for (NSWindow *win in allWindows) {
        if (win == mainWin) continue;
        if (![win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) continue;
        if (!groupMatch && [groupNumbers containsObject:@(win.windowNumber)]) groupMatch = win;
        if (!matchesTab(win)) continue;
        id abstractWebView = [win valueForKey:@"webView"];
        WKWebView *wkView = (WKWebView *)[abstractWebView performSelector:@selector(nativeWebView)];
        NSString *winUrl = wkView.URL.absoluteString ?: @"";
        NSString *origUrl = [win valueForKey:@"blinkeredOriginalURLString"] ?: @"";
        if ([winUrl isEqualToString:tabUrl] || [origUrl isEqualToString:tabUrl]) { exactMatch = win; break; }
        if (!hostMatch) hostMatch = win;
    }
    return exactMatch ?: (hostMatch ?: groupMatch);
}

// Receives messages posted by Blinkered classroom pages via window.webkit.messageHandlers.blinkered.postMessage(...)
- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message
{
    if (![message.body isKindOfClass:[NSDictionary class]]) return;
    NSDictionary *body = message.body;
    NSString *type = body[@"type"];

    // ── [R1-1] THE GATE — an ALLOW-LIST, above the dispatch, with an EMPTY exemption list ────────
    //
    // This used to be a deny-list naming setQuitPassword and updateURLFilter. That is the wrong
    // SHAPE, and the history proves it rather than merely suggesting it: the list was amended three
    // times in three review rounds, and an inventory written expressly to close the enumeration
    // still passed two escapes — including focusWindow/reloadWindow, which handed arbitrary JS to
    // the shell's main frame from any frame of any origin, and which that inventory had marked
    // "Safe". A deny-list requires its author to have thought of every dangerous message. This
    // handler's own comment says that assumption is unavailable: script-message handlers are
    // exposed to EVERY frame of EVERY origin in webviews sharing this configuration.
    //
    // Above the dispatch and allow-listing means a handler added later is gated BY DEFAULT — the
    // only property that survives a future author who has not read any of this.
    //
    // The exemption list is EMPTY, and must stay empty. Every bridge type is posted only by our own
    // shell pages (content.html, home-content.html, student.html), each always a main frame at our
    // own origin, so there is NO legitimate cross-origin sender for any message and an exemption
    // buys literally nothing. The four types once proposed for exemption were not inert either:
    // showAutoUpdateSetup puts a movable native card above the lock and fronts the root-daemon
    // admin-password ceremony; focusMainContent mutates window levels and steals focus;
    // studentSessionActive performs a write; setTopInset is a process-global mutated from an
    // untrusted frame.
    //
    // Prerequisite: blinkeredReportBridgeTamper: is THROTTLED (see above). Without that, inverting
    // this gate would turn `for(;;) postMessage({type:'getOpenWindows'})` into an unbounded POST
    // flood on a locked child's device — closing an escape by opening a denial of service.
    if (![self blinkeredTrustedBridgeOrigin:message]) {
        WKSecurityOrigin *o = message.frameInfo.securityOrigin;
        NSString *originDesc = [NSString stringWithFormat:@"%@://%@", o.protocol ?: @"?", o.host ?: @"?"];
        // Log through the same throttle as the report: under the allow-list every type is
        // reachable from any frame, so an unthrottled DDLogError is a disk-fill primitive on a
        // locked device — the same failure the report throttle exists to prevent.
        if ([self blinkeredShouldReportTamperKey:[NSString stringWithFormat:@"log|%@|%@", type ?: @"?", originDesc]]) {
            DDLogError(@"Blinkered SECURITY: rejected bridge message '%@' from untrusted origin %@ — "
                       @"no handler ran. (Further refusals for this type+origin are throttled.)",
                       type ?: @"<none>", originDesc);
        }
        [self blinkeredReportBridgeTamper:type origin:originDesc];
        return;
    }

    if ([type isEqualToString:@"setQuitPassword"]) {
        // [R1-1] Home sessions NEVER take a page-pushed quit password: the server bakes the parent's
        // Master Exit Code into the home .seb, and it must stay the ONLY native quit credential —
        // accepting one here (even from our own origin) would let page state overwrite the offline
        // exit boundary. Class sessions keep the flow (the teacher page legitimately pushes it).
        NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString *homeSessionPath = [[[dirs firstObject] stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"home_session.json"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:homeSessionPath]) {
            DDLogError(@"Blinkered SECURITY: setQuitPassword refused during a home session — the master code stays authoritative");
            return;
        }
        NSString *hash = body[@"hash"];
        // Expect a 64-char lowercase hex SHA-256 digest.
        if ([hash isKindOfClass:[NSString class]] && hash.length == 64) {
            [[NSUserDefaults standardUserDefaults] setSecureObject:hash
                forKey:@"org_safeexambrowser_SEB_hashedQuitPassword"];
            DDLogInfo(@"Blinkered: quit password updated for current class session");
        }
    } else if ([type isEqualToString:@"updateURLFilter"]) {
        // Blinkered: the server pushed a fresh navigation allow-list mid-session (a parent/teacher
        // added a site). Rebuild the shared URL filter live so the new domain is navigable on the next
        // navigation — no re-lock. `rules` = array of {action,active,expression,regex} (same shape as
        // the .seb config's URLFilterRules). Passing the current page URL keeps this shell reachable.
        NSArray *rules = body[@"rules"];
        if ([rules isKindOfClass:[NSArray class]]) {
            BOOL enable = [body[@"enable"] boolValue];
            NSError *error = [[SEBURLFilter sharedSEBURLFilter] updateFilterRulesWithArray:rules
                                                                                    enable:enable
                                                                                  startURL:message.webView.URL];
            if (error) {
                DDLogError(@"Blinkered: live URL-filter update failed: %@", error.localizedDescription);
            } else {
                DDLogInfo(@"Blinkered: URL filter updated live — %lu rule(s), enabled=%d", (unsigned long)rules.count, enable);
            }
        }
    } else if ([type isEqualToString:@"quit"]) {
        // Native end-of-session quit, mirroring Windows 1.0.0.145 (`case "quit": controller.Quit()`).
        // The page posts this the moment the session ends; without it the Mac sits through the page's
        // 2 s /seb-quit fallback before anything happens.
        //
        // Deliberately NOT refused during home sessions the way setQuitPassword is: a home unlock is
        // legitimately page-initiated (server → poll → page), so refusing here would break the
        // feature. setQuitPassword's refusal protects a CREDENTIAL that must stay the parent's; this
        // message carries no credential, and the origin gate above is what makes it safe. It is also
        // strictly stronger than the /seb-quit URL interceptor it front-runs, which fires on any
        // frame's navigation with no origin check at all.
        if (BlinkeredTeardownStarted()) {
            DDLogInfo(@"Blinkered: bridge quit ignored — teardown already running");
            return;
        }
        // Optional childId, so exitSEB's cookie save targets the right jar on an assigned device that
        // never went through a picker login. INVARIANT: never adopt a childId when no child session is
        // active. On a shared device sitting at the profile picker, blinkeredFocusChildId is correctly
        // nil and the save belongs in the global cookies.json — adopting there would divert that
        // store's residual cookies into one kid's jar and break isolation. Enforced by requiring the
        // .seb this session launched from to name the SAME child, so adoption can only ever set the
        // value the config already declared and never invent one from page state.
        NSString *childId = body[@"childId"];
        if ([childId isKindOfClass:[NSString class]] && childId.length > 0 &&
            self.blinkeredFocusChildId.length == 0) {
            NSString *cfgChild = [[NSUserDefaults standardUserDefaults] secureStringForKey:@"org_safeexambrowser_SEB_blinkeredFocusChildId"];
            if (cfgChild.length > 0 && [cfgChild isEqualToString:childId]) {
                self.blinkeredFocusChildId = childId;
                DDLogInfo(@"Blinkered: bridge quit adopted the page's childId (matches this session's config)");
            } else {
                DDLogWarn(@"Blinkered: bridge quit childId NOT adopted — this session's config names no matching child, cookies save to the global store");
            }
        }
        // Async to main: the same path /seb-quit takes, and it lets the page's postMessage return
        // before the app starts tearing itself down.
        dispatch_async(dispatch_get_main_queue(), ^{
            DDLogInfo(@"Blinkered: native quit requested by the page");
            [[NSNotificationCenter defaultCenter] postNotificationName:@"quitLinkDetected" object:self];
        });
    } else if ([type isEqualToString:@"masterCodeExit"]) {
        // ── §14.2 — the lock page's Master Exit Code box, validated ON THE DEVICE ─────────────────
        //
        // Phase 1's field asks the server, so out of Wi-Fi range — the exact situation a Master Exit
        // Code exists for — the parent's own code could do nothing. This routes it to the same
        // credential Cmd+Q has always accepted offline: the hash the server baked into this
        // session's .seb.
        //
        // Everything that decides ANYTHING lives in SEBController (blinkeredMasterCodeBridgeRequest:)
        // next to the Cmd+Q path it reuses verbatim — the class-session refusal, the empty-bake
        // refusal, the compare, the throttle, the quit. This side does two things only: prove the
        // sender is a home lock page of ours, and carry the reply back to the frame that asked.
        //
        // [P2R2-13] THE HOME-SESSION GATE IS A PROPER PATH CHECK. `[url containsString:@"/home/"]`
        // would be satisfied by any allow-listed page at our own origin carrying `/home/` in a query
        // string or fragment — `https://blinkered.com.au/x?next=/home/`. The origin gate above proves
        // the host; this proves the page. NSURL.path excludes query and fragment by construction.
        WKWebView *sender = message.webView;
        NSURL *pageURL = sender.URL;
        BOOL isHomePage = message.frameInfo.mainFrame &&
                          ([pageURL.path isEqualToString:@"/home"] || [pageURL.path hasPrefix:@"/home/"]);
        if (!isHomePage) {
            DDLogWarn(@"Blinkered SECURITY: masterCodeExit refused — sender is not a main-frame home lock page (path '%@', mainFrame %d)",
                      pageURL.path ?: @"<none>", message.frameInfo.mainFrame);
            return;
        }
        NSString *code = body[@"code"];
        NSString *pageSessionId = body[@"sessionId"];
        NSString *replyId = body[@"replyId"];
        if (![code isKindOfClass:[NSString class]] || ![replyId isKindOfClass:[NSString class]] || replyId.length == 0) return;
        if (![pageSessionId isKindOfClass:[NSString class]]) pageSessionId = nil;
        // [P2R1 F6]/[P2R2-16] The reply carries ONE OF THREE ENUMERATED LITERALS chosen by us — never
        // anything the page sent — and goes to `message.webView`, the frame that actually asked,
        // rather than the main webview by assumption. It still travels through the §0-sanitised
        // escaping helper: the correlation id is page-supplied, and the one thing this project has
        // learned repeatedly is that "but this value is ours" stops being true one refactor later.
        void (^reply)(NSString *) = ^(NSString *verdict) {
            NSString *safeVerdict = ([verdict isEqualToString:@"ok"] || [verdict isEqualToString:@"slow-down"]) ? verdict : @"mismatch";
            dispatch_async(dispatch_get_main_queue(), ^{
                NSString *js = [NSString stringWithFormat:@"window.__blinkeredMasterCodeReply && window.__blinkeredMasterCodeReply(%@, %@)",
                                [SEBAbstractWebView blinkeredJSStringLiteral:replyId],
                                [SEBAbstractWebView blinkeredJSStringLiteral:safeVerdict]];
                [sender evaluateJavaScript:js completionHandler:nil];
            });
        };
        [[NSNotificationCenter defaultCenter] postNotificationName:@"BlinkeredMasterCodeBridgeRequest"
                                                            object:nil
                                                          userInfo:@{ @"code": code,
                                                                      @"sessionId": pageSessionId ?: @"",
                                                                      @"reply": [reply copy] }];

    } else if ([type isEqualToString:@"chromeReady"]) {
        // #44 health signal, posted by every shell page once its chrome has rendered. It had no
        // handler here at all — it fell off the end of this chain in silence, which is exactly the
        // shape the terminal `else` below now makes visible. [P2R2-14] uses it as the page-navigation
        // signal that clears the bounded double-Cmd+Q latch.
        [[NSNotificationCenter defaultCenter] postNotificationName:@"BlinkeredPageChromeReady" object:nil];

    } else if ([type isEqualToString:@"profileSwitch"]) {
        // Shared home device: each child has their own cookie jar. On 'leave' we save the
        // outgoing child's cookies; on 'login' we wipe the jar and restore the incoming child's
        // saved cookies BEFORE navigating to their session — so each kid stays logged into their
        // own Alto (and any cookie-based site) and never inherits another child's session.
        [self blinkeredProfileSwitch:body[@"action"] childId:body[@"childId"] url:body[@"url"] webView:message.webView];
    } else if ([type isEqualToString:@"studentSessionActive"]) {
        // A focus/class session is running (content.html in the kiosk). It was launched from a
        // student.html tab that the web app returns to on exit, so the terminate handler must NOT
        // open a second student.html tab.
        self.blinkeredWebReturn = YES;
    } else if ([type isEqualToString:@"openDashboard"]) {
        // A shared-device home session is ending — open the kid-mode student dashboard in the
        // default browser WITH the device token (read from agent.json) so the kid lands on the
        // profile picker after unlock instead of a stale Clerk view. We open student.html here, so
        // the terminate handler must NOT open it again (or the kid gets a duplicate tab).
        self.blinkeredWebReturn = YES;
        NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString *agentJson = [[[dirs firstObject] stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
        NSData *credData = [NSData dataWithContentsOfFile:agentJson];
        NSString *did = nil, *dtok = nil;
        if (credData) {
            NSDictionary *creds = [NSJSONSerialization JSONObjectWithData:credData options:0 error:nil];
            if ([creds isKindOfClass:[NSDictionary class]]) {
                if ([creds[@"id"] isKindOfClass:[NSString class]]) did = creds[@"id"];
                if ([creds[@"token"] isKindOfClass:[NSString class]]) dtok = creds[@"token"];
            }
        }
        NSCharacterSet *qa = [NSCharacterSet URLQueryAllowedCharacterSet];
        NSString *dashURL = (did.length && dtok.length)
            ? [NSString stringWithFormat:@"https://blinkered.com.au/student.html?did=%@&dtok=%@",
                [did stringByAddingPercentEncodingWithAllowedCharacters:qa],
                [dtok stringByAddingPercentEncodingWithAllowedCharacters:qa]]
            : @"https://blinkered.com.au/student.html";
        DDLogInfo(@"Blinkered: openDashboard bridge — opening %@ in default browser (token=%d)", dashURL, (did.length && dtok.length));
        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:dashURL]];
        });
    } else if ([type isEqualToString:@"closeAdditionalWindows"]) {
        // Teacher hit Clear — close all popup browser windows, keep only the main window.
        // Evaluate window.close() inside each popup's WKWebView — this is the same path SEB
        // uses for JS-initiated closes (webViewDidClose: → closeWebView:), bypassing the
        // abstractWebView.window lookup that silently fails because that custom property is
        // never populated for popup windows.
        dispatch_async(dispatch_get_main_queue(), ^{
            NSWindow *mainWin = [self valueForKey:@"mainBrowserWindow"];
            NSArray *allWindows = [[NSApplication sharedApplication].windows copy];
            for (NSWindow *win in allWindows) {
                if (win == mainWin || !win.isVisible) continue;
                if (![win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) continue;
                id abstractWebView = [win valueForKey:@"webView"];
                if (!abstractWebView) continue;
                WKWebView *wkView = (WKWebView *)[abstractWebView performSelector:@selector(nativeWebView)];
                if ([wkView isKindOfClass:[WKWebView class]]) {
                    // Pause + mute any playing media FIRST so audio stops even if the window
                    // refuses to close — WebKit blocks window.close() once the user has
                    // navigated the window (e.g. searched YouTube and opened a video), which
                    // otherwise left the audio playing after a Clear. Then ask it to close.
                    [wkView evaluateJavaScript:@"(function(){try{document.querySelectorAll('video,audio').forEach(function(m){try{m.pause();m.muted=true;m.src='';}catch(e){}});}catch(e){}try{window.close();}catch(e){}})()" completionHandler:nil];
                }
                // Native close as the reliable fallback for navigated windows that ignore
                // window.close() — guarantees the window (and its media) actually goes away.
                [win close];
            }
        });

    } else if ([type isEqualToString:@"getOpenWindows"]) {
        // Return a JSON array of { url, title } for every visible SEBBrowserWindow except the
        // main window. Called by content.html every second to populate the window-switcher tab bar.
        // Result is delivered by evaluating window.__blinkeredWindowsCallback(json) in the main view.
        dispatch_async(dispatch_get_main_queue(), ^{
            NSWindow *mainWin = [self valueForKey:@"mainBrowserWindow"];
            // Get the main window's WKWebView so we can call back into it.
            WKWebView *mainWkView = nil;
            id mainAbstract = [mainWin valueForKey:@"webView"];
            if (mainAbstract) {
                WKWebView *v = (WKWebView *)[mainAbstract performSelector:@selector(nativeWebView)];
                if ([v isKindOfClass:[WKWebView class]]) mainWkView = v;
            }
            NSMutableArray *result = [NSMutableArray array];
            NSArray *allWindows = [[NSApplication sharedApplication].windows copy];
            for (NSWindow *win in allWindows) {
                if (win == mainWin || !win.isVisible) continue;
                if (![win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) continue;
                id abstractWebView = [win valueForKey:@"webView"];
                if (!abstractWebView) continue;
                WKWebView *wkView = (WKWebView *)[abstractWebView performSelector:@selector(nativeWebView)];
                if (![wkView isKindOfClass:[WKWebView class]]) continue;
                NSString *urlStr = wkView.URL.absoluteString ?: @"";
                NSString *titleStr = (wkView.title.length > 0) ? wkView.title : (wkView.URL.host ?: urlStr);
                // id / originatingUrl / opener / active let the page render per-window chips
                // (documents a site opened) and address one window unambiguously: id is the
                // windowNumber (stable while the window is alive), opener is the windowNumber
                // of the window whose page opened this one (0 = tab-opened), active marks the
                // key window so the chips can highlight the one in front. Older pages ignore
                // the extra fields; older apps omit them and the page renders no chips.
                NSString *origStr = [win valueForKey:@"blinkeredOriginalURLString"] ?: @"";
                NSNumber *openerNum = [win valueForKey:@"blinkeredOpenerWindowNumber"] ?: @(0);
                [result addObject:@{ @"url": urlStr, @"title": titleStr,
                                     @"id": @(win.windowNumber),
                                     @"originatingUrl": origStr,
                                     @"opener": openerNum,
                                     @"active": @(win == [NSApplication sharedApplication].keyWindow) }];
                // (No "Switch tab" button injected — the student returns to the tab bar
                //  via the bottom-edge reveal, and the regular site tabs handle focus.)
            }
            // These are page-controlled window TITLES and URLs going into the SHELL's main frame.
            // The old inline NSJSONSerialization was safe, but only by accident — JSON output is a
            // JS-literal subset under ES2019 and not before, i.e. one character class away from §0.
            // Through the helper it is safe on purpose, and U+2028/U+2029 are escaped explicitly.
            NSString *jsonStr = [SEBAbstractWebView blinkeredJSLiteral:result fallback:@"[]"];
            if (mainWkView) {
                NSString *js = [NSString stringWithFormat:@"window.__blinkeredWindowsCallback && window.__blinkeredWindowsCallback(%@)", jsonStr];
                [mainWkView evaluateJavaScript:js completionHandler:nil];
            }
        });

    } else if ([type isEqualToString:@"focusWindow"]) {
        // Bring a specific open SEBBrowserWindow to the front. With an `id` (windowNumber,
        // from a window chip) the exact window is targeted; by URL, the MOST RECENTLY USED
        // matching window of the site wins — see the ordering note below.
        NSString *targetUrl = body[@"url"];
        if (![targetUrl isKindOfClass:[NSString class]] || targetUrl.length == 0) return;
        NSInteger targetNumber = [body[@"id"] isKindOfClass:[NSNumber class]] ? [body[@"id"] integerValue] : 0;
        dispatch_async(dispatch_get_main_queue(), ^{
            NSWindow *mainWin = [self valueForKey:@"mainBrowserWindow"];
            // A chip click names one specific window — focus exactly it. If it has since
            // closed, fall through to the URL matching below (never reopen a chip's window).
            if (targetNumber > 0) {
                for (NSWindow *win in [[NSApplication sharedApplication].windows copy]) {
                    if (win.windowNumber == targetNumber && win != mainWin &&
                        [win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) {
                        [win makeKeyAndOrderFront:nil];
                        return;
                    }
                }
            }
            // Check if the request is to focus the main window itself (from a "Switch tab" button).
            id mainAbstractForFocus = [mainWin valueForKey:@"webView"];
            if (mainAbstractForFocus) {
                WKWebView *mv = (WKWebView *)[mainAbstractForFocus performSelector:@selector(nativeWebView)];
                if ([mv isKindOfClass:[WKWebView class]]) {
                    NSString *mainUrlForFocus = mv.URL.absoluteString ?: @"";
                    if ([mainUrlForFocus isEqualToString:targetUrl] ||
                        [[mv.URL host] isEqualToString:([NSURL URLWithString:targetUrl].host ?: @"")]) {
                        [mainWin makeKeyAndOrderFront:nil];
                        return;
                    }
                }
            }
            // Which window does this tab mean? One rule, shared with reloadWindow and
            // navigateWindow — see -blinkeredTabTargetWindowForURL:...
            NSMutableSet *groupNumbers = nil;
            NSWindow *target = [self blinkeredTabTargetWindowForURL:targetUrl
                                                        mainWindow:mainWin
                                                        allWindows:[[NSApplication sharedApplication].windows copy]
                                                    orderedWindows:[[NSApplication sharedApplication].orderedWindows copy]
                                                      groupNumbers:&groupNumbers];
            // Rig diagnostic: the tab's resolved window group and what this click surfaced. Pairs with
            // the "site window N opened (opener window M)" line to show grouping end to end.
            DDLogInfo(@"[Blinkered] focusWindow(%@, id=%ld): group %@ -> %@.",
                      targetUrl, (long)targetNumber, groupNumbers,
                      target ? [NSString stringWithFormat:@"window %ld", (long)target.windowNumber] : @"no window (reopen or no-op)");
            // No "any open window" fallback — that focused the wrong site when several were
            // open. Only reopen when this site genuinely has no window.
            if (target) {
                // Re-show the existing window — never reloads the page.
                [target makeKeyAndOrderFront:nil];
            } else if ([body[@"reopenIfMissing"] boolValue]) {
                NSLog(@"[Blinkered] focusWindow: no surviving window — reopening %@", targetUrl);
                // No alive window for this tab (it was genuinely closed, not just hidden
                // or occluded). Ask the home page to open it fresh. Returning to a window
                // that still exists goes through makeKeyAndOrderFront above, so the page
                // keeps its state — only a truly-closed tab reaches this reopen path.
                id mainAbs = [mainWin valueForKey:@"webView"];
                WKWebView *mainWk = nil;
                if (mainAbs) {
                    WKWebView *v = (WKWebView *)[mainAbs performSelector:@selector(nativeWebView)];
                    if ([v isKindOfClass:[WKWebView class]]) mainWk = v;
                }
                if (mainWk) {
                    // targetUrl is page-supplied and this runs in the SHELL's main
                    // frame, so it must go through the one escaping helper — see
                    // +blinkeredJSStringLiteral:. The literal carries its own quotes.
                    NSString *js = [NSString stringWithFormat:@"window.__blinkeredReopenTab && window.__blinkeredReopenTab(%@)",
                                    [SEBAbstractWebView blinkeredJSStringLiteral:targetUrl]];
                    [mainWk evaluateJavaScript:js completionHandler:nil];
                }
            }
        });

    } else if ([type isEqualToString:@"reloadWindow"]) {
        // The home tab bar's ↻ Reload button — reload the open site window whose URL matches, so a
        // kid can recover a page whose JavaScript died or only half-rendered (no error fires for
        // that case, so SEB's "Load Error / Retry" alert never appears). Reloading re-requests the
        // SAME already-allowed URL, so it can't be used to escape the lockdown. Window resolution
        // is the SHARED rule — see -blinkeredTabTargetWindowForURL:...
        NSString *targetUrl = body[@"url"];
        if (![targetUrl isKindOfClass:[NSString class]] || targetUrl.length == 0) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            NSWindow *mainWin = [self valueForKey:@"mainBrowserWindow"];
            NSMutableSet *groupNumbers = nil;
            NSWindow *target = [self blinkeredTabTargetWindowForURL:targetUrl
                                                        mainWindow:mainWin
                                                        allWindows:[[NSApplication sharedApplication].windows copy]
                                                    orderedWindows:[[NSApplication sharedApplication].orderedWindows copy]
                                                      groupNumbers:&groupNumbers];
            DDLogInfo(@"[Blinkered] reloadWindow(%@): group %@ -> %@.",
                      targetUrl, groupNumbers,
                      target ? [NSString stringWithFormat:@"window %ld", (long)target.windowNumber] : @"no window (reopen or no-op)");
            if (target) {
                id abstractWebView = [target valueForKey:@"webView"];
                WKWebView *wkView = (WKWebView *)[abstractWebView performSelector:@selector(nativeWebView)];
                if ([wkView isKindOfClass:[WKWebView class]]) { [wkView reload]; }
                [target makeKeyAndOrderFront:nil];
            } else if ([body[@"reopenIfMissing"] boolValue]) {
                // No surviving window for this tab — reopen it fresh, which is itself a clean load.
                id mainAbs = [mainWin valueForKey:@"webView"];
                WKWebView *mainWk = nil;
                if (mainAbs) {
                    WKWebView *v = (WKWebView *)[mainAbs performSelector:@selector(nativeWebView)];
                    if ([v isKindOfClass:[WKWebView class]]) mainWk = v;
                }
                if (mainWk) {
                    // targetUrl is page-supplied and this runs in the SHELL's main
                    // frame, so it must go through the one escaping helper — see
                    // +blinkeredJSStringLiteral:. The literal carries its own quotes.
                    NSString *js = [NSString stringWithFormat:@"window.__blinkeredReopenTab && window.__blinkeredReopenTab(%@)",
                                    [SEBAbstractWebView blinkeredJSStringLiteral:targetUrl]];
                    [mainWk evaluateJavaScript:js completionHandler:nil];
                }
            }
        });

    } else if ([type isEqualToString:@"navigateWindow"]) {
        // The home tab bar's ‹ / › back/forward buttons — move the tab's window through its
        // history. Window resolution is the SHARED rule (see -blinkeredTabTargetWindowForURL:...);
        // goBack/goForward are no-ops at the ends of history, and history holds only
        // already-allowed pages, so this can't escape the lockdown.
        NSString *targetUrl = body[@"url"];
        NSString *direction = body[@"direction"];   // "back" (default) | "forward"
        if (![targetUrl isKindOfClass:[NSString class]] || targetUrl.length == 0) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            NSWindow *mainWin = [self valueForKey:@"mainBrowserWindow"];
            NSMutableSet *groupNumbers = nil;
            NSWindow *target = [self blinkeredTabTargetWindowForURL:targetUrl
                                                        mainWindow:mainWin
                                                        allWindows:[[NSApplication sharedApplication].windows copy]
                                                    orderedWindows:[[NSApplication sharedApplication].orderedWindows copy]
                                                      groupNumbers:&groupNumbers];
            DDLogInfo(@"[Blinkered] navigateWindow(%@, %@): group %@ -> %@.",
                      targetUrl, direction ?: @"back", groupNumbers,
                      target ? [NSString stringWithFormat:@"window %ld", (long)target.windowNumber] : @"no window (no-op)");
            if (target) {
                id abstractWebView = [target valueForKey:@"webView"];
                WKWebView *wkView = (WKWebView *)[abstractWebView performSelector:@selector(nativeWebView)];
                if ([wkView isKindOfClass:[WKWebView class]]) {
                    if ([direction isEqualToString:@"forward"]) { [wkView goForward]; } else { [wkView goBack]; }
                }
                [target makeKeyAndOrderFront:nil];
            }
        });

    } else if ([type isEqualToString:@"setTopInset"]) {
        // The home page reports its always-visible top tab-bar height so full-window site
        // windows (opened afterwards) leave that strip free at the top of the screen.
        extern CGFloat blinkeredTopInset;
        double h = [body[@"height"] doubleValue];
        blinkeredTopInset = (h > 0 && h < 200) ? h : 0;

    } else if ([type isEqualToString:@"focusMainContent"]) {
        // An embeddable site was selected in the main window's iframe — ask SEBController
        // to raise the main window above the open site windows and show it opaque.
        [[NSNotificationCenter defaultCenter] postNotificationName:@"BlinkeredFocusMainContent" object:nil];

    } else if ([type isEqualToString:@"showAutoUpdateSetup"]) {
        // Parent picked "Set up automatic updates" (locked-session ⋯ menu / student-dashboard device
        // setup) — ask SEBController to (re)open the updater setup card. See PARENT_SETUP_REGISTRATION.md.
        [[NSNotificationCenter defaultCenter] postNotificationName:@"BlinkeredShowAutoUpdateSetup" object:nil];

    } else if ([type isEqualToString:@"showSessionMenu"]) {
        // The home tab bar's identity menu (avatar + name → Join class / Message parent / Switch
        // user / Exit). A DOM dropdown can't float over the open site windows — they're separate
        // native windows stacked in FRONT of the main page — and raising the main window exposes
        // its dark "open in a separate window" backdrop. So the page asks for a REAL NSMenu at the
        // trigger's location: menu windows live at popup level (~101), far above the kiosk windows
        // (NSMainMenuWindowLevel+2), so the dropdown appears over the site exactly as expected.
        // The picked item id is returned via window.__blinkeredMenuPick('<id>') in the same page;
        // items are display-only labels — all behavior stays in the page's own handlers.
        NSArray *items = body[@"items"];
        double anchorX = [body[@"x"] doubleValue];   // CSS px — trigger's LEFT edge
        double anchorY = [body[@"y"] doubleValue];   // CSS px — just below the trigger
        WKWebView *pageView = message.webView;
        if (![items isKindOfClass:[NSArray class]] || items.count == 0 || !pageView) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!pageView.window) return;
            NSMenu *menu = [[NSMenu alloc] initWithTitle:@""];
            menu.autoenablesItems = NO;
            for (NSDictionary *it in items) {
                if (![it isKindOfClass:[NSDictionary class]]) continue;
                NSString *itemId = it[@"id"];
                NSString *label = it[@"label"];
                if (![itemId isKindOfClass:[NSString class]]) continue;
                if ([itemId isEqualToString:@"-"]) { [menu addItem:[NSMenuItem separatorItem]]; continue; }
                if (![label isKindOfClass:[NSString class]] || label.length == 0) continue;
                NSMenuItem *mi = [[NSMenuItem alloc] initWithTitle:label
                                                            action:@selector(blinkeredSessionMenuPicked:)
                                                     keyEquivalent:@""];
                mi.target = self;
                mi.representedObject = @{ @"id": itemId, @"webView": pageView };
                // Same per-item icon the Windows menu shows: the page posts a semantic name (calendar,
                // class, message, site, switch, exit); map it to an SF Symbol. Template images, so the
                // menu tints them to match its text in light/dark and when highlighted.
                NSImage *icon = [self blinkeredSessionMenuIconForName:it[@"icon"]];
                if (icon) mi.image = icon;
                [menu addItem:mi];
            }
            if (menu.numberOfItems == 0) return;
            // CSS px == view points (no page zoom in the kiosk). WKWebView is not flipped, so
            // convert the page's top-origin y to the view's bottom-origin coordinate space.
            NSPoint loc = NSMakePoint(anchorX, pageView.isFlipped ? anchorY
                                                                  : pageView.bounds.size.height - anchorY);
            [menu popUpMenuPositioningItem:nil atLocation:loc inView:pageView];
        });

    } else if ([type isEqualToString:@"closeWindow"]) {
        // Close ONE extra window by its windowNumber — the × on a window chip (a document /
        // popup a site opened). Guards: never the main window, only SEBBrowserWindows, so the
        // worst an errant call can do is close a site window the tab bar can reopen. Media is
        // paused + muted via JS first (WebKit blocks window.close() once the user has navigated
        // the window), then the native close routes through windowWillClose: → closeWebView:
        // for the dock-menu / webview bookkeeping — the same teardown closeAdditionalWindows uses.
        NSInteger winNumber = [body[@"id"] isKindOfClass:[NSNumber class]] ? [body[@"id"] integerValue] : 0;
        if (winNumber <= 0) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            NSWindow *mainWin = [self valueForKey:@"mainBrowserWindow"];
            for (NSWindow *win in [[NSApplication sharedApplication].windows copy]) {
                if (win.windowNumber != winNumber) continue;
                if (win == mainWin || ![win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) return;
                id abstractWebView = [win valueForKey:@"webView"];
                if (abstractWebView) {
                    WKWebView *wkView = (WKWebView *)[abstractWebView performSelector:@selector(nativeWebView)];
                    if ([wkView isKindOfClass:[WKWebView class]]) {
                        [wkView evaluateJavaScript:@"(function(){try{document.querySelectorAll('video,audio').forEach(function(m){try{m.pause();m.muted=true;m.src='';}catch(e){}});}catch(e){}try{window.close();}catch(e){}})()" completionHandler:nil];
                    }
                }
                [win close];
                return;
            }
        });

    } else if ([type isEqualToString:@"clearSiteWindows"]) {
        // Teacher cleared the screen — hide every open site window and bring the main
        // (home) window, showing the "cleared" overlay, back to the front.
        dispatch_async(dispatch_get_main_queue(), ^{
            NSWindow *mainWin = [self valueForKey:@"mainBrowserWindow"];
            for (NSWindow *win in [[NSApplication sharedApplication].windows copy]) {
                if (win == mainWin) continue;
                if (![win isKindOfClass:NSClassFromString(@"SEBBrowserWindow")]) continue;
                [win orderOut:nil];
            }
            [mainWin makeKeyAndOrderFront:nil];
        });

    } else {
        // [P2R1 F6] An unknown type LOGS; it does not vanish. This chain used to end with no else at
        // all, and that silence is not a cosmetic gap: a page posting a type this build does not have
        // got no handler AND no reply AND no trace — which is how a page could sit forever on
        // "Checking…" waiting for an answer from a build that never knew the question. The bridge's
        // own timeout is what makes that survivable; this is what makes it diagnosable. Throttled by
        // the same key as the origin refusals, so a `for(;;) postMessage({type:'x'})` cannot fill the
        // disk of a locked child's device.
        if ([self blinkeredShouldReportTamperKey:[NSString stringWithFormat:@"unknown|%@", type ?: @"<none>"]]) {
            DDLogWarn(@"Blinkered: bridge message '%@' has no handler in this build — ignored, no reply sent. "
                      @"(Further messages of this type are throttled.)", type ?: @"<none>");
        }
    }
}


- (void)initSessionSettings
{
    // Activate the custom URL protocol if necessary (embedded certs or pinning available)
    [self conditionallyInitCustomHTTPProtocol];

    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    self.quitURL = [[[preferences secureStringForKey:@"org_safeexambrowser_SEB_quitURL"] stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]] lowercaseString];
    sendHashKeys = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_sendBrowserExamKey"] || [self isUsingServerBEK];
    self.configKey = [preferences secureObjectForKey:@"org_safeexambrowser_configKey"];
    self.browserExamKeySalt = [preferences secureObjectForKey:@"org_safeexambrowser_SEB_examKeySalt"];
    NSData *currentBrowserExamKey = [preferences secureDataForKey:@"org_safeexambrowser_currentData"];
    self.browserExamKey = currentBrowserExamKey;
    webPageShowURLAlways = ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_browserWindowShowURL"] == browserWindowShowURLAlways);
    newWebPageShowURLAlways = ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_newBrowserWindowShowURL"] == browserWindowShowURLAlways);
    _allowDownloads = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDownUploads"] && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDownloads"];
#if TARGET_OS_OSX
    _allowUploads = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDownUploads"] && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowUploads"];
#else
    _allowUploads = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDownUploads"] && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowUploadsiOS"];
#endif
    [self setDownloadDirectory];
}


- (void)setDownloadDirectory
{
#if TARGET_OS_OSX
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_useTemporaryDownUploadDirectory"]) {
        downloadDirectoryURL = [self.delegate getTempDownUploadDirectory];
    } else {
        downloadDirectoryURL = [self downloadDirectoryURL];
    }
#else
    downloadDirectoryURL = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].firstObject;
#endif
}

#if TARGET_OS_OSX
- (NSURL *)downloadDirectoryURL
{
    NSString *downloadPath = [[NSUserDefaults standardUserDefaults] secureStringForKey:@"org_safeexambrowser_SEB_downloadDirectoryOSX"];
    downloadPath = [downloadPath stringByExpandingTildeInPath];
    NSURL *downloadDirectory;
    NSFileManager *fileManager= [NSFileManager defaultManager];
    BOOL isDir;

    if (downloadPath.length == 0 || [downloadPath isEqualToString:@"~/Downloads"] || !([fileManager fileExistsAtPath:downloadPath isDirectory:&isDir] && isDir)) {
        // If there's no path saved in preferences or a non-existing directory, use Downloads directory
        NSError *error;
        downloadDirectory = [fileManager URLForDirectory:NSDownloadsDirectory inDomain:NSUserDomainMask appropriateForURL:fileManager.homeDirectoryForCurrentUser create:NO error:&error];
        DDLogInfo(@"Default Downloads directory set.");
    } else {
        downloadDirectory = [NSURL fileURLWithPath:downloadPath isDirectory:YES];
    }
    return downloadDirectory;
}
#endif


- (void) resetBEKCK
{
    _browserExamKey = nil;
    _configKey = nil;
    // Force recalculating Config Key
    [[NSUserDefaults standardUserDefaults] setSecureObject:[NSData data] forKey:@"org_safeexambrowser_configKey"];
    [[SEBCryptor sharedSEBCryptor] updateEncryptedUserDefaults:YES updateSalt:NO];
}


- (BOOL)isNavigationAllowedMainWebView:(BOOL)mainWebView
{
    NSString *keyAllowNavigation;
    if (mainWebView) {
        keyAllowNavigation = @"org_safeexambrowser_SEB_allowBrowsingBackForward";
    } else {
        keyAllowNavigation = @"org_safeexambrowser_SEB_newBrowserWindowNavigation";
    }
    
    return [[NSUserDefaults standardUserDefaults] secureBoolForKey:keyAllowNavigation];
}

- (BOOL)isReloadAllowedMainWebView:(BOOL)mainWebView
{
    NSString *keyAllowReload;
    if (mainWebView) {
        keyAllowReload = @"org_safeexambrowser_SEB_browserWindowAllowReload";
    } else {
        keyAllowReload = @"org_safeexambrowser_SEB_newBrowserWindowAllowReload";
    }
    
    return [[NSUserDefaults standardUserDefaults] secureBoolForKey:keyAllowReload];
}

- (BOOL)showReloadWarningMainWebView:(BOOL)mainWebView
{
    NSString *keyShowReloadWarning;
    if (mainWebView) {
        keyShowReloadWarning = @"org_safeexambrowser_SEB_showReloadWarning";
    } else {
        keyShowReloadWarning = @"org_safeexambrowser_SEB_newBrowserWindowShowReloadWarning";
    }
    
    return [[NSUserDefaults standardUserDefaults] secureBoolForKey:keyShowReloadWarning];
}

- (void) quitSession
{
    examSessionCookiesAlreadyCleared = NO;
}

- (void) resetBrowser
{
    self.downloadingInTemporaryWebView = NO;
    self.temporaryWebView = nil;
    [self.delegate removeTempDownUploadDirectory];
    [[MyGlobals sharedMyGlobals] setDownloadPath:[NSMutableArray new]];
    [[MyGlobals sharedMyGlobals] setLastDownloadPath:0];

    self.browserExamKey = nil;
    self.configKey = nil;
    self.customSEBUserAgent = nil;
    [self initSessionSettings];

    void (^completionHandler)(void) = ^void() {
        // Additional commands for resetting browser
    };
    if (examSessionCookiesAlreadyCleared == NO) {
        if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_examSessionClearCookiesOnStart"]) {
            // Empties all cookies, caches and credential stores, removes disk files, flushes in-progress
            // downloads to disk, and ensures that future requests occur on a new socket.
            DDLogInfo(@"-[SEBBrowserController resetBrowser] Cookies, caches and credential stores are being reset when starting new browser session (examSessionClearCookiesOnStart = true)");
            [self resetAllCookiesWithCompletionHandler:^{
                completionHandler();
            }];
            return;
        }
    } else {
        // reset the flag when it was true before
        examSessionCookiesAlreadyCleared = NO;
    }
    [self transferCookiesToWKWebViewWithCompletionHandler:completionHandler];
}


/// Save the default user agent of the installed WebKit version
+ (void) createSEBUserAgentFromDefaultAgent:(NSString *)defaultUserAgent
{
    // Get WebKit version number string to use it as Safari version
    NSRange webKitSubstring = [defaultUserAgent rangeOfString:@"AppleWebKit/"];
    NSString *webKitVersion;
    if (webKitSubstring.location != NSNotFound && (webKitSubstring.location + webKitSubstring.length) < defaultUserAgent.length) {
        webKitVersion = [defaultUserAgent substringFromIndex:webKitSubstring.location + webKitSubstring.length];
        webKitVersion = [[webKitVersion stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] componentsSeparatedByString:@" "][0];
    } else {
        webKitVersion = SEBUserAgentDefaultSafariVersion;
    }
    defaultUserAgent = [defaultUserAgent stringByAppendingString:[NSString stringWithFormat:@" %@/%@", SEBUserAgentDefaultBrowserSuffix, webKitVersion]];
    [[MyGlobals sharedMyGlobals] setValue:defaultUserAgent forKey:@"defaultUserAgent"];
}


- (NSString *) openWebpagesTitlesString
{
    // SEB Screen Proctoring metadata is not localized
    NSArray *openWebpagesTitles = [_delegate openWebpagesTitles];
    NSString *openWebpagesTitlesMetaDataString = @"Main Window: ";
    NSString *openWebpagesTitlesMetaDataKeyString = nil;
    for (NSString *pageTitle in openWebpagesTitles) {
        NSString *sanitizedPageTitle = @"Untitled";
        if ([pageTitle isKindOfClass:[NSString class]]) {
            sanitizedPageTitle = [NSString stringWithFormat:@"%@", pageTitle.length > 0 ? pageTitle : sanitizedPageTitle];
        }
        sanitizedPageTitle = [self windowTitleByRemovingSEBVersionString:sanitizedPageTitle];
        if (openWebpagesTitlesMetaDataKeyString) {
            openWebpagesTitlesMetaDataString = [openWebpagesTitlesMetaDataString stringByAppendingFormat:@", %@: %@", openWebpagesTitlesMetaDataKeyString, sanitizedPageTitle];
        } else {
            openWebpagesTitlesMetaDataString = [openWebpagesTitlesMetaDataString stringByAppendingString:sanitizedPageTitle];
            openWebpagesTitlesMetaDataKeyString = @"Additional Window";
        }
    }
    return openWebpagesTitlesMetaDataString;
}


- (NSString *) windowTitleByRemovingSEBVersionString:(NSString *)browserWindowTitle
{
    NSUInteger sebVersionWindowTitelSeparatorLocation = [browserWindowTitle rangeOfString:browserWindowTitleSeparator].location;
    if (sebVersionWindowTitelSeparatorLocation != NSNotFound) {
        browserWindowTitle = [browserWindowTitle substringFromIndex:MIN(sebVersionWindowTitelSeparatorLocation+5, browserWindowTitle.length-1)];
    }
    return browserWindowTitle;
}


#pragma mark - SEBAbstractWebViewNavigationDelegate Methods

- (NSData *)browserExamKey
{
    if (_browserExamKey.length == 0) {
        self.browserExamKey = [[NSUserDefaults standardUserDefaults] secureObjectForKey:@"org_safeexambrowser_currentData"];
    }
    return _browserExamKey;
}

- (NSData *)configKey
{
    if (_configKey.length == 0) {
        self.configKey = [[NSUserDefaults standardUserDefaults] secureObjectForKey:@"org_safeexambrowser_configKey"];
    }
    return _configKey;
}


- (void) transferCookiesToWKWebViewWithCompletionHandler:(void (^)(void))completionHandler
{
    // Adopt a config-provided PER-CHILD jar (assigned device / focus). The .seb sets blinkeredFocusChildId so
    // every session keys cookies to the kid — consistent across their lock + focus, isolated from siblings on
    // a shared device.
    //
    // CRITICAL: the app process AND this controller survive across lock→unlock→lock, so we must NOT trust a
    // stale blinkeredFocusChildId from a previous kid's session. Detect a NEW .seb via its config key
    // (rewritten in NSUserDefaults on every config load) and, on change, re-read the child from config +
    // re-arm the owner check. Without this, a second lock as a different kid kept the first kid's child id →
    // no wipe → the new kid inherited the previous kid's logins (Rupert saw Rory's Alto, 3.6.166/3.6.167).
    // A runtime profileSwitch (shared picker) sets the child WITHOUT loading a new config, so its choice is
    // preserved: same config key → we don't re-read → the picker's child stands.
    {
        NSUserDefaults *prefs = [NSUserDefaults standardUserDefaults];
        NSData *liveConfigKey = [prefs secureObjectForKey:@"org_safeexambrowser_configKey"];
        NSString *cfgChild = [prefs secureStringForKey:@"org_safeexambrowser_SEB_blinkeredFocusChildId"];
        BOOL configKeyChanged = (liveConfigKey.length > 0 && ![liveConfigKey isEqualToData:self.blinkeredCookieConfigKey]);
        BOOL configChildChanged = ((cfgChild.length > 0 || self.blinkeredCookieConfigChild.length > 0) &&
                                   ![(cfgChild ?: @"") isEqualToString:(self.blinkeredCookieConfigChild ?: @"")]);
        BOOL newConfig = configKeyChanged || configChildChanged;
        if (newConfig) {
            // A fresh lock/focus session: config is authoritative — replace any stale child left over from the
            // previous session (this controller survives lock→unlock→lock) and re-arm the owner check so a
            // kid-change wipes the previous kid's residual store. A runtime profileSwitch (shared picker) does
            // NOT change the config, so its child is preserved (neither signal fires for a same-.seb popup).
            self.blinkeredCookieConfigKey = liveConfigKey;
            self.blinkeredCookieConfigChild = cfgChild;
            self.blinkeredFocusChildId = cfgChild.length > 0 ? cfgChild : nil;
            self.blinkeredCookieMigrateFromConfig = (cfgChild.length > 0) ? [prefs secureBoolForKey:@"org_safeexambrowser_SEB_blinkeredCookieMigrate"] : NO;
            self.blinkeredCookieOwnerChecked = NO;
            // Per-child DATA WIPE: the parent removed these kids from this device → delete each one's saved
            // cookie jar so nothing of theirs remains on the Mac. One-shot (the server consumes the queue when
            // it emits this key, so it won't repeat). A removed kid is never THIS session's child, so the
            // shared store is handled by the owner-check wipe below; here we just erase their on-disk jar file.
            id clearList = [prefs secureObjectForKey:@"org_safeexambrowser_SEB_blinkeredClearChildData"];
            if ([clearList isKindOfClass:[NSArray class]]) {
                for (id cid in (NSArray *)clearList) {
                    if ([cid isKindOfClass:[NSString class]] && ((NSString *)cid).length > 0) {
                        NSString *jar = [self blinkeredCookiePathForChild:(NSString *)cid];
                        if ([[NSFileManager defaultManager] fileExistsAtPath:jar]) {
                            [[NSFileManager defaultManager] removeItemAtPath:jar error:nil];
                            NSLog(@"BLINKERED transferCookies: wiped removed child %@ cookie jar", cid);
                        }
                    }
                }
            }
        } else if (self.blinkeredFocusChildId.length == 0 && cfgChild.length > 0) {
            // Best-effort first fill when no config-change signal was available; never clobbers a live child.
            self.blinkeredFocusChildId = cfgChild;
            self.blinkeredCookieMigrateFromConfig = [prefs secureBoolForKey:@"org_safeexambrowser_SEB_blinkeredCookieMigrate"];
        }
    }
    // Blinkered per-child isolation: restore ONLY this child's saved cookies and IGNORE the global
    // cookies.json — otherwise SEB re-injects the previous user's cookies into every new window (the Alto
    // popup), leaking the last kid's logins.
    if (self.blinkeredFocusChildId.length > 0) {
        WKWebsiteDataStore *dataStore = self.wkWebViewConfiguration.websiteDataStore;
        WKHTTPCookieStore *cookieStore = dataStore.httpCookieStore;
        // Restore THIS child's jar (migrating the legacy global jar first if flagged) into the store.
        void (^restoreChildJar)(void) = ^{
            NSArray<NSHTTPCookie *> *saved = [self blinkeredLoadCookiesForChild:self.blinkeredFocusChildId];
            // One-time migration (ASSIGNED devices only): the kid's logins are still in the legacy global
            // cookies.json → seed their jar from it so they DON'T re-login, then delete the global jar so
            // nothing else inherits it. Fail-safe: if the global jar is empty/absent we fall through to an
            // empty jar — a wrong migration can only ever cost one login, never wipe a real jar.
            if (saved.count == 0 && self.blinkeredCookieMigrateFromConfig) {
                NSArray<NSHTTPCookie *> *globalCookies = [self blinkeredLoadGlobalCookies];
                if (globalCookies.count > 0) {
                    [self blinkeredSaveCookies:globalCookies forChild:self.blinkeredFocusChildId];
                    [self blinkeredDeleteGlobalCookieFile];
                    saved = globalCookies;
                    NSLog(@"BLINKERED transferCookies: migrated %lu global cookies → child %@ (assigned, one-time)", (unsigned long)saved.count, self.blinkeredFocusChildId);
                }
                self.blinkeredCookieMigrateFromConfig = NO;   // attempt only once
            }
            NSLog(@"BLINKERED transferCookies: focus child %@ → restoring %lu saved cookies (ignoring cookies.json)", self.blinkeredFocusChildId, (unsigned long)saved.count);
            if (saved.count == 0) { run_block_on_ui_thread(^{ completionHandler(); }); return; }
            dispatch_group_t waitGroup = dispatch_group_create();
            for (NSHTTPCookie *cookie in saved) {
                dispatch_group_enter(waitGroup);
                [cookieStore setCookie:cookie completionHandler:^{ dispatch_group_leave(waitGroup); }];
            }
            dispatch_group_notify(waitGroup, dispatch_get_main_queue(), ^{ completionHandler(); });
        };
        // ONCE per launch: if the PERSISTENT store belongs to a DIFFERENT kid than this session's child, WIPE
        // it first so the new kid never inherits the previous kid's residual cookies. This closes the
        // shared-device leak where a SERVER-SIDE child switch relaunches the session without going through the
        // picker's own wipe (Rupert saw Rory's Alto, 3.6.166). Same kid → no wipe (keep their cookies +
        // localStorage). Subsequent new windows skip this (checked flag), so a mid-session popup never wipes.
        if (!self.blinkeredCookieOwnerChecked) {
            self.blinkeredCookieOwnerChecked = YES;
            NSString *owner = [self blinkeredReadCookieStoreOwner];
            [self blinkeredWriteCookieStoreOwner:self.blinkeredFocusChildId];
            if (owner.length > 0 && ![owner isEqualToString:self.blinkeredFocusChildId]) {
                NSLog(@"BLINKERED transferCookies: store owner %@ ≠ session child %@ → wiping before restore", owner, self.blinkeredFocusChildId);
                NSSet *types = [WKWebsiteDataStore allWebsiteDataTypes];
                [dataStore removeDataOfTypes:types modifiedSince:[NSDate distantPast] completionHandler:^{
                    // removeDataOfTypes is unreliable for cookies — authoritatively delete every cookie too.
                    [cookieStore getAllCookies:^(NSArray<NSHTTPCookie *> *remaining) {
                        dispatch_group_t delGroup = dispatch_group_create();
                        for (NSHTTPCookie *c in remaining) { dispatch_group_enter(delGroup); [cookieStore deleteCookie:c completionHandler:^{ dispatch_group_leave(delGroup); }]; }
                        dispatch_group_notify(delGroup, dispatch_get_main_queue(), ^{ restoreChildJar(); });
                    }];
                }];
                return;
            }
        }
        restoreChildJar();
        return;
    }
    // No per-child jar → the legacy GLOBAL cookies.json (an older assigned device, before per-child jars).
    NSArray<NSHTTPCookie *> *globalCookies = [self blinkeredLoadGlobalCookies];
    NSLog(@"BLINKERED transferCookies: global cookies.json → %lu cookies", (unsigned long)globalCookies.count);
    if (globalCookies.count > 0) {
        WKHTTPCookieStore *cookieStore = self.wkWebViewConfiguration.websiteDataStore.httpCookieStore;
        dispatch_group_t waitGroup = dispatch_group_create();
        for (NSHTTPCookie *cookie in globalCookies) {
            dispatch_group_enter(waitGroup);
            [cookieStore setCookie:cookie completionHandler:^{ dispatch_group_leave(waitGroup); }];
        }
        dispatch_group_notify(waitGroup, dispatch_get_main_queue(), ^{ completionHandler(); });
        return;
    }
    run_block_on_ui_thread(^{ completionHandler(); });
}


// Create browser user agent according to settings
- (NSString*) customSEBUserAgent
{
    if (!_customSEBUserAgent) {
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        NSString* versionString = [[MyGlobals sharedMyGlobals] infoValueForKey:@"CFBundleShortVersionString"];
        NSString *overrideUserAgent;
        NSString *browserUserAgentSuffix = [[preferences secureStringForKey:@"org_safeexambrowser_SEB_browserUserAgent"] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (browserUserAgentSuffix.length != 0) {
            browserUserAgentSuffix = [NSString stringWithFormat:@" %@", browserUserAgentSuffix];
        }
        
        BOOL useCustomUserAgentVerbatim = NO;
#if TARGET_OS_IPHONE
        if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_browserUserAgentiOS"] == browserUserAgentModeiOSDefault) {
            overrideUserAgent = [[MyGlobals sharedMyGlobals] valueForKey:@"defaultUserAgent"];
        } else if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_browserUserAgentiOS"] == browserUserAgentModeiOSMacDesktop) {
            overrideUserAgent = SEBiOSUserAgentDesktopMac;
        } else {
            overrideUserAgent = [preferences secureStringForKey:@"org_safeexambrowser_SEB_browserUserAgentiOSCustom"];
        }
#else
        if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_browserUserAgentMac"] == browserUserAgentModeMacDefault) {
            overrideUserAgent = [[MyGlobals sharedMyGlobals] valueForKey:@"defaultUserAgent"];
        } else {
            overrideUserAgent = [preferences secureStringForKey:@"org_safeexambrowser_SEB_browserUserAgentMacCustom"];
            // Blinkered: a CUSTOM Mac user agent (set by our locked-session .seb config) is used
            // VERBATIM — we do NOT append the SEB version tokens below. Sites like Canva reject any
            // user agent containing an unrecognised product token (e.g. "SEB/3.6", and even
            // "Blinkered/3.6"), serving an "unsupported browser" page; a clean Safari UA loads them
            // normally. iOS and default-Mac behaviour are unchanged.
            useCustomUserAgentVerbatim = YES;
        }
#endif
        // Add "SEB <version number>" to the browser's user agent, so the LMS SEB plugins recognize us
        if (!useCustomUserAgentVerbatim) {
            overrideUserAgent = [overrideUserAgent stringByAppendingString:[NSString stringWithFormat:@" %@/%@ %@/3.5.4 %@/3.6 %@", SEBUserAgentDefaultSuffix, versionString, SEBUserAgentDefaultSuffix, SEBUserAgentDefaultSuffix, browserUserAgentSuffix]];
        }
        _customSEBUserAgent = overrideUserAgent;
    }
    return _customSEBUserAgent;
}


// The "blinkered" script message handler is this controller (registered in
// wkWebViewConfiguration). Exposed via the navigation delegate so the modern
// WebView can re-register it on its freshly-built user content controller.
- (id<WKScriptMessageHandler>)blinkeredScriptMessageHandler
{
    return self;
}

- (WKWebViewConfiguration *)wkWebViewConfiguration
{
    if (!_wkWebViewConfiguration) {
        _wkWebViewConfiguration = [[WKWebViewConfiguration alloc] init];
        DDLogDebug(@"Created new WKWebViewConfiguration %@", _wkWebViewConfiguration);
        // Older macOS (pre-26): disable ITP via WKWebsiteDataStore
        if ([_wkWebViewConfiguration.websiteDataStore respondsToSelector:@selector(_setResourceLoadStatisticsEnabled:)]) {
            [_wkWebViewConfiguration.websiteDataStore _setResourceLoadStatisticsEnabled:NO];
        }
        // macOS 26+: the above API was removed; use the storage blocking policy instead.
        // 0 = _WKStorageBlockingPolicyAllowAll — no ITP, no third-party cookie blocking.
        // Resolved at runtime because the symbol is absent from the SDK's .tbd stub.
        static _WKPreferencesSetStorageBlockingPolicyFn setStorageBlockingPolicy = NULL;
        static dispatch_once_t setStorageBlockingPolicyOnce;
        dispatch_once(&setStorageBlockingPolicyOnce, ^{
            setStorageBlockingPolicy = (_WKPreferencesSetStorageBlockingPolicyFn)dlsym(RTLD_DEFAULT, "_WKPreferencesSetStorageBlockingPolicy");
        });
        if (setStorageBlockingPolicy) {
            setStorageBlockingPolicy((__bridge void *)_wkWebViewConfiguration.preferences, 0);
        }
        // Pre-grant "user interaction" trust for alto.guru so ITP treats it as first-party
        // from the very first iframe load, without needing a prior popup/full-window visit.
        if ([_wkWebViewConfiguration.websiteDataStore respondsToSelector:@selector(_statisticsSetHasHadUserInteraction:value:completionHandler:)]) {
            [_wkWebViewConfiguration.websiteDataStore _statisticsSetHasHadUserInteraction:@"alto.guru" value:YES completionHandler:nil];
        }
        // Belt-and-suspenders: request storage access from within any alto.guru iframe so
        // the browser grants cookie access even if ITP is partially active.
        NSString *storageAccessScript = @"(function() {"
            "if (window !== window.top && location.hostname.endsWith('alto.guru') && document.requestStorageAccess) {"
            "  document.requestStorageAccess().catch(function(){});"
            "}"
            "})();";
        WKUserScript *storageAccessUserScript = [[WKUserScript alloc]
            initWithSource:storageAccessScript
            injectionTime:WKUserScriptInjectionTimeAtDocumentStart
            forMainFrameOnly:NO];
        [_wkWebViewConfiguration.userContentController addUserScript:storageAccessUserScript];
        [_wkWebViewConfiguration.userContentController addScriptMessageHandler:self name:@"blinkered"];
    }
    
    // Set media playback properties on new webview
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if (@available(macOS 10.12, iOS 11.0, *)) {
        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_browserMediaAutoplay"] == NO) {
            _wkWebViewConfiguration.mediaTypesRequiringUserActionForPlayback = WKAudiovisualMediaTypeAll;
        } else {
            _wkWebViewConfiguration.mediaTypesRequiringUserActionForPlayback =
            (![preferences secureBoolForKey:@"org_safeexambrowser_SEB_browserMediaAutoplayAudio"] ? WKAudiovisualMediaTypeAudio : 0) |
            (![preferences secureBoolForKey:@"org_safeexambrowser_SEB_browserMediaAutoplayVideo"] ? WKAudiovisualMediaTypeVideo : 0);
        }
    }
    
#if TARGET_OS_IPHONE
    UIUserInterfaceIdiom currentDevice = UIDevice.currentDevice.userInterfaceIdiom;
    if (currentDevice == UIUserInterfaceIdiomPad) {
        _wkWebViewConfiguration.allowsInlineMediaPlayback = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_mobileAllowInlineMediaPlayback"];
    } else {
        _wkWebViewConfiguration.allowsInlineMediaPlayback = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_mobileCompactAllowInlineMediaPlayback"];
    }
    _wkWebViewConfiguration.allowsPictureInPictureMediaPlayback = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_mobileAllowPictureInPictureMediaPlayback"];
    _wkWebViewConfiguration.dataDetectorTypes = WKDataDetectorTypeNone;
#else
    BOOL developerExtrasEnabled = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDeveloperConsole"];
    [_wkWebViewConfiguration.preferences setValue:[NSNumber numberWithBool:developerExtrasEnabled] forKey: @"developerExtrasEnabled"];
#endif
    if (@available(macOS 10.13, *)) {
        _wkWebViewConfiguration.allowsAirPlayForMediaPlayback = NO;
    }
    return _wkWebViewConfiguration;
}


- (NSString *) webPageTitle:(NSString *)title orURL:(NSURL *)url mainWebView:(BOOL)mainWebView
{
    NSString *webPageTitle;
    if (!title) {
        title = [self urlOrPlaceholderForURL:url.absoluteString];
    }
    if (mainWebView) {
        if (webPageShowURLAlways) {
            webPageTitle = url.absoluteString;
        } else {
            webPageTitle = title;
        }
    } else {
        if (newWebPageShowURLAlways) {
                webPageTitle = url.absoluteString;
            } else {
                webPageTitle = title;
            }
    }
    return webPageTitle;
}


- (NSString *) urlOrPlaceholderForURL:(NSString *)url
{
    NSString *urlOrPlaceholder = [self urlPlaceholderTitleForWebpage];
    return urlOrPlaceholder ? urlOrPlaceholder : url;
}


// Delegate method which returns a placeholder text in case settings
// don't allow to display its URL
- (NSString *) urlPlaceholderTitleForWebpage
{
    NSString *placeholderString = nil;
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    if ([self.delegate isMainBrowserWebViewActive]) {
        if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_browserWindowShowURL"] == browserWindowShowURLNever) {
            placeholderString = NSLocalizedString(@"the exam page", @"");
        }
    } else {
        if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_newBrowserWindowShowURL"] == browserWindowShowURLNever) {
            placeholderString = NSLocalizedString(@"the webpage", @"");
        }
    }
    return placeholderString;
}


- (NSString *) startURLQueryParameter:(NSURL**)url
{
    // Check URL for additional query string
    NSString *startURLQueryParameter = nil;
    NSString *queryString = (*url).query;
    if (queryString.length > 0) {
        NSArray *additionalQueryStrings = [queryString componentsSeparatedByString:@"?"];
        // There is an additional query string if the full query URL component itself containts
        // a query separator character "?"
        if (additionalQueryStrings.count == 2) {
            // Cache the additional query string for later use
            startURLQueryParameter = additionalQueryStrings.lastObject;
            // Replace the full query string in the download URL with the first query component
            // (which is the actual query of the SEB config download URL)
            queryString = additionalQueryStrings.firstObject;
            NSURLComponents *urlComponents = [NSURLComponents componentsWithURL:*url resolvingAgainstBaseURL:NO];
            if (queryString.length == 0) {
                queryString = nil;
            }
            urlComponents.query = queryString;
            *url = urlComponents.URL;
        }
    }

    return startURLQueryParameter;
}


- (NSString *) backToStartURLString
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    NSString* backToStartURL;
    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_restartExamUseStartURL"]) {
        // Check if SEB Server started the exam and we have its Start URL
        backToStartURL = _delegate.startURL.absoluteString;
        DDLogInfo(@"Will load Start URL in main browser window: %@", [self urlOrPlaceholderForURL:backToStartURL]);
    } else {
        backToStartURL = [preferences secureStringForKey:@"org_safeexambrowser_SEB_restartExamURL"];
        DDLogInfo(@"Will load Back to Start URL in main browser window: %@", [self urlOrPlaceholderForURL:backToStartURL]);
    }
    return backToStartURL;
}


static NSString *urlStrippedFragment(NSURL* url)
{
    NSString *absoluteRequestURL = url.absoluteString;
    
    NSString *fragment = url.fragment;
    NSString *requestURLStrippedFragment;
    if (fragment.length) {
        // if there is a fragment
        requestURLStrippedFragment = [absoluteRequestURL substringToIndex:absoluteRequestURL.length - fragment.length - 1];
    } else requestURLStrippedFragment = absoluteRequestURL;
    DDLogVerbose(@"Full absolute request URL: %@", absoluteRequestURL);
    DDLogVerbose(@"Request URL used to calculate RequestHash: %@", requestURLStrippedFragment);
    return requestURLStrippedFragment;
}


- (NSString *) pageJavaScript
{
    return _javaScriptFunctions;
}


- (BOOL) isUsingServerBEK
{
    return self.serverBrowserExamKey != nil;
}


- (NSURLRequest *) modifyRequest:(NSURLRequest *)request
{
    NSURL *url = request.URL;
    
    //// Check if quit URL has been clicked (regardless of current URL Filter)
    
    // Trim a possible trailing slash "/"    
    NSString *absoluteRequestURLTrimmed = [[url.absoluteString stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]] lowercaseString];

    if ([absoluteRequestURLTrimmed isEqualToString:_quitURL]) {
        [[NSNotificationCenter defaultCenter]
         postNotificationName:@"quitLinkDetected" object:self];
    }
    

    NSDictionary<NSString *, NSString *> *_Nullable headerFields;
    headerFields = [request allHTTPHeaderFields];
//    DDLogVerbose(@"All HTTP header fields: %@", headerFields);
        
    NSMutableURLRequest *modifiedRequest = [request mutableCopy];

    // Browser Exam Key
    
    [modifiedRequest setValue:[self browserExamKeyForURL:url] forHTTPHeaderField:SEBBrowserExamKeyHeaderKey];
    
    // Config Key
    
    [modifiedRequest setValue:[self configKeyForURL:url] forHTTPHeaderField:SEBConfigKeyHeaderKey];
    
    // User Agent (necessary since building with iOS 17 SDK
    
    if ([request valueForHTTPHeaderField:UserAgentHeaderKey].length >= 0) {
        [modifiedRequest setValue:[self customSEBUserAgent] forHTTPHeaderField:UserAgentHeaderKey];
    }
    
//    headerFields = [modifiedRequest allHTTPHeaderFields];
//        DDLogVerbose(@"All HTTP header fields in modified request: %@", headerFields);
    
    return [modifiedRequest copy];
}


- (NSString *) browserExamKeyForURL:(NSURL *)url
{
    unsigned char hashedChars[32];
    if (self.serverBrowserExamKey) {
        [self.serverBrowserExamKey getBytes:hashedChars length:32];
    } else {
        NSData *browserExamKey = self.browserExamKey;
        [browserExamKey getBytes:hashedChars length:32];
    }
        
    NSMutableString* browserExamKeyString = [[NSMutableString alloc] initWithString:urlStrippedFragment(url)];
    for (NSUInteger i = 0 ; i < 32 ; ++i) {
        [browserExamKeyString appendFormat: @"%02x", hashedChars[i]];
    }
    const char *urlString = [browserExamKeyString UTF8String];
    CC_SHA256(urlString,
              (uint)strlen(urlString),
              hashedChars);
    
    NSMutableString* hashedString = [[NSMutableString alloc] initWithCapacity:32];
    for (NSUInteger i = 0 ; i < 32 ; ++i) {
        [hashedString appendFormat: @"%02x", hashedChars[i]];
    }
    return hashedString;
}


- (NSString *) configKeyForURL:(NSURL *)url
{
    unsigned char hashedChars[32];

    [self.configKey getBytes:hashedChars length:32];
    
#ifdef DEBUG
    DDLogVerbose(@"Current Config Key: %@", self.configKey);
#endif
    
    NSMutableString* configKeyString = [[NSMutableString alloc] initWithString:urlStrippedFragment(url)];
    for (NSUInteger i = 0 ; i < 32 ; ++i) {
        [configKeyString appendFormat: @"%02x", hashedChars[i]];
    }
#ifdef DEBUG
    DDLogVerbose(@"Current request URL + Config Key: %@", configKeyString);
#endif
    const char *urlString = [configKeyString UTF8String];
    CC_SHA256(urlString,
              (uint)strlen(urlString),
              hashedChars);
    
    NSMutableString* hashedConfigKeyString = [[NSMutableString alloc] initWithCapacity:32];
    for (NSUInteger i = 0 ; i < 32 ; ++i) {
        [hashedConfigKeyString appendFormat: @"%02x", hashedChars[i]];
    }
    return hashedConfigKeyString;
}


- (NSString *) appVersion
{
    NSString *displayName = [[MyGlobals sharedMyGlobals] infoValueForKey:@"CFBundleDisplayName"];
    NSString *versionString = [[MyGlobals sharedMyGlobals] infoValueForKey:@"CFBundleShortVersionString"];
    NSString *buildNumber = [[MyGlobals sharedMyGlobals] infoValueForKey:@"CFBundleVersion"];
    NSString *bundleID = [[MyGlobals sharedMyGlobals] infoValueForKey:@"CFBundleIdentifier"];
    NSString *appVersion = [NSString stringWithFormat:@"%@_macOS_%@_%@_%@", displayName, versionString, buildNumber, bundleID];
    return appVersion;
}


- (void)customHTTPProtocol:(CustomHTTPProtocol *)protocol logWithFormat:(NSString *)format arguments:(va_list)arguments;
{
    NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
    DDLogVerbose(@"%@", message);
}


// Called by the CustomHTTPProtocol class to let the delegate know that a regular HTTP request
// or a XMLHttpRequest (XHR) successfully completed loading. The delegate can use this callback
// for example to scan the newly received HTML data
- (void)sessionTaskDidCompleteSuccessfully:(NSURLSessionTask *)task
{
    [_delegate sessionTaskDidCompleteSuccessfully:task];
}


// Check if reconfiguring is allowed depending on settings and referrer URL (if one is passed)
- (BOOL) isReconfiguringAllowedFromURL:(NSURL *)url
{
    // If a quit password is set (= running in exam session),
    // then check if the reconfigure config file URL matches the setting
    // examSessionReconfigureConfigURL (where the wildcard character '*' can be used)
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    BOOL secureSession = preferences.secureSession;
    BOOL secureSessionReconfigureAllow = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_examSessionReconfigureAllow"];
    BOOL secureSessionReconfigureURLMatch = NO;
    if (url && secureSession && secureSessionReconfigureAllow) {
        NSString *sebConfigURLString = url.absoluteString;
        NSPredicate *predicate = [NSPredicate predicateWithFormat:@"self LIKE %@", [preferences secureStringForKey:@"org_safeexambrowser_SEB_examSessionReconfigureConfigURL"]];
        secureSessionReconfigureURLMatch = [predicate evaluateWithObject:sebConfigURLString];
    }
    // Check if SEB is in exam mode (= quit password is set) and exam is running,
    // but reconfiguring is allowed by setting and the reconfigure config URL matches the setting
    // or SEB isn't in exam mode, but is running with settings for starting an exam and the
    // reconfigure allow setting isn't set
    if ((secureSession && !(secureSessionReconfigureAllow && secureSessionReconfigureURLMatch)) ||
        (!secureSession && NSUserDefaults.userDefaultsPrivate && !secureSessionReconfigureAllow)) {
        // If yes, we don't download the .seb file
        return NO;
    } else {
        return YES;
    }
}


#pragma mark - Server authentication

//- (void) URLSession:(NSURLSession *)session
//didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
// completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
//{
//    NSURLProtectionSpace *protectionSpace = challenge.protectionSpace;
//    NSString *host = protectionSpace.host;
//    NSString *authenticationMethod = protectionSpace.authenticationMethod;
//    NSString *realm = protectionSpace.realm;
//    SecTrustRef serverTrust = protectionSpace.serverTrust;
//    DDLogInfo(@"URLSession: %@ didReceiveChallenge for host %@ with authenticationMethod: %@, realm: %@, serverTrust: %@", session, host, authenticationMethod, realm, serverTrust);
//
//    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
//}


-(void) conditionallyInitCustomHTTPProtocol
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    SEBCertServices *sharedCertService = [SEBCertServices sharedInstance];
    authorizedHosts = [NSMutableArray new];
    previousAuthentications = [NSMutableArray new];
    pinEmbeddedCertificates = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_pinEmbeddedCertificates"];

    // Flush cached embedded certificates (as they might have changed with new settings)
    [sharedCertService flushCachedCertificates];
    
    usingEmbeddedCertificates = pinEmbeddedCertificates ||
    sharedCertService.caCerts.count > 0 ||
    sharedCertService.tlsCerts.count > 0 ||
    sharedCertService.debugCerts.count > 0;
    
    // Check if the custom URL protocol needs to be activated
#if TARGET_OS_IPHONE
    if (YES) // necessary for setting UserAgent string since building with iOS 17 SDK
#else
    if (usingEmbeddedCertificates)
#endif
    {
        _usingCustomURLProtocol = YES;
        // Become delegate of and register custom SEB NSURL protocol class
        [CustomHTTPProtocol setDelegate:self];
        [CustomHTTPProtocol start];
    } else {
        _usingCustomURLProtocol = NO;
        // Deactivate the protocol
        [CustomHTTPProtocol stop];
    }
}


- (BOOL)customHTTPProtocol:(CustomHTTPProtocol *)protocol canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    assert(protocol != nil);
#pragma unused(protocol)
    assert(protectionSpace != nil);
    
    // We accept any username/password and server trust authentication challenges.
    NSString *authenticationMethod = protectionSpace.authenticationMethod;
    
    return [authenticationMethod isEqual:NSURLAuthenticationMethodHTTPBasic] ||
    [authenticationMethod isEqual:NSURLAuthenticationMethodHTTPDigest] ||
    [authenticationMethod isEqual:NSURLAuthenticationMethodNTLM] ||
    [authenticationMethod isEqual:NSURLAuthenticationMethodServerTrust];
}


/*
 * CLIENT CONFIGURATION
 *
 * SEB internally maintains two arrays of SecCertificateRef certificate objects, tlsCerts and caCerts.
 * These are populated by parsing the SEB config file key 'embeddedCertificates/certificateDataBase64' or 'certificateDataWin'.
 *
 * The handling of these certs depends on the setting of 'pinEmbeddedCertificates' in the SEB config file.
 *
 * Pinning can be used as an additional layer of security to decrease the MITM attack surface by avoiding
 * the use of CA roots which are included in the OS trust store for which there is no legitimate reason
 * to actually trust them because the server endpoint's CA is known to us and its root cert (and intermediate
 * CA certs, if applicable) are embedded. Pinning can also be performed directly against an SSL/TLS server
 * cert (usually self-signed) for which we have prior knowledge of the public key (this cert must also
 * be embedded for matching purposes)
 *
 * If 'pinEmbeddedCertificates' is FALSE and tlsCerts, debugCerts and caCerts are empty, the standard
 * OS trust store behavior applies.
 *
 * If 'pinEmbeddedCertificates' is FALSE and tlsCerts, debugCerts and/or caCerts contains certificates, these
 * certificates extend the system trust store (as if you had manually added them to the system trust store)
 *
 * If 'pinEmbeddedCertificates' is FALSE and only tlsCerts are present (i.e. no caCerts), the exact
 * behavior of SEB Windows 2.1+ is expected for backward compatibility (these are typically self-signed
 * SSL/TLS certificates being added to the trust store as they do not chain back to an OS trusted CA root)
 *
 * If 'pinEmbeddedCertificates' is TRUE and tlsCerts, debugCerts and caCerts are empty, all HTTPS traffic will
 * be rejected (these arrays could be empty if they were filtered out during loading, e.g. due to date
 * expirations, except debugCerts which are not checked for expiration)
 *
 * If 'pinEmbeddedCertificates' is TRUE and caCerts are available, only the embedded CA roots can act
 * as trust anchors. If any of the embedded root caCerts result in trust being established, HTTPS traffic
 * will be permitted otherwise pinned tlsCerts/debugCerts will be checked. If tlsCerts and debugCerts is empty,
 * HTTPS traffic will be rejected, else each embedded SSL/TLS certificate's public key will be compared against
 * the server SSL/TLS leaf certificate public key and HTTPS traffic will be allowed if a match is detected and
 * other evaluation checks are passed (domain match, expiration, etc.) in case of tlsCerts.
 *
 * For compatibility, the above behavior must be exactly duplicated by other client ports.
 *
 * SERVER CONFIGURATION
 *
 * If the server's SSL/TLS leaf cert is not directly signed by a trusted CA root cert then in addition to the
 * server's SSL/TLS leaf cert the intermediate CA certs must be sent as a bundle during SSL/TLS handshake
 * (this also applies if a private CA intermediate cert was used to sign the server's SSL/TLS cert, except
 * the private CA root cert needs to be embedded). If the server will be sending a self-signed SSL/TLS cert
 * then a copy of the leaf cert must be embedded in the client's config file.
 */
- (void)customHTTPProtocol:(CustomHTTPProtocol *)protocol didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) = ^void(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) {
        switch (disposition) {
            case NSURLSessionAuthChallengeUseCredential:
                [self.authenticatingProtocol resolveAuthenticationChallenge:self.authenticatingProtocol.pendingChallenge withCredential:credential];
                self.authenticatingProtocol = nil;
                break;
                
            case NSURLSessionAuthChallengeCancelAuthenticationChallenge:
            {
                //            [_authenticatingProtocol performSelectorOnMainThread:@selector(stopLoading)
                //                                                            withObject:NULL waitUntilDone:YES];
                if (self.pendingChallenge == self.authenticatingProtocol.pendingChallenge) {
                    DDLogDebug(@"_pendingChallenge is same as _authenticatingProtocol.pendingChallenge");
                } else {
                    DDLogDebug(@"_pendingChallenge is not same as _authenticatingProtocol.pendingChallenge");
                }
                [challenge.sender cancelAuthenticationChallenge:challenge];
                self.authenticatingProtocol = nil;
                break;
            }
                
            case NSURLSessionAuthChallengePerformDefaultHandling:
                [self.authenticatingProtocol resolveAuthenticationChallenge:self.authenticatingProtocol.pendingChallenge withCredential:credential];
                self.authenticatingProtocol = nil;
                break;
                
            default:
                [self.authenticatingProtocol resolveAuthenticationChallenge:self.authenticatingProtocol.pendingChallenge withCredential:credential];
                self.authenticatingProtocol = nil;
                break;
        }
    };
    
    _authenticatingProtocol = protocol;
    DDLogInfo(@"CustomHTTPProtocol: %@ didReceiveAuthenticationChallenge: %@", protocol, challenge);
    [self didReceiveAuthenticationChallenge:challenge completionHandler:completionHandler];
}

// We don't need to implement -customHTTPProtocol:didCancelAuthenticationChallenge: because we always resolve
// the challenge synchronously within -customHTTPProtocol:didReceiveAuthenticationChallenge:.


- (void)enteredUsername:(NSString *)username password:(NSString *)password returnCode:(NSInteger)returnCode
{
    DDLogDebug(@"Enter username password sheetDidEnd with return code: %ld", (long)returnCode);
    
    if (_pendingChallengeCompletionHandler) {
        if (returnCode == SEBEnterPasswordOK) {
            _lastUsername = username;
            NSURLCredential *newCredential = [NSURLCredential credentialWithUser:username
                                                       password:password
                                                    persistence:NSURLCredentialPersistenceForSession];
            NSString *host = _pendingChallenge.protectionSpace.host;
            NSDictionary *newAuthentication = @{ authenticationHost : host, authenticationUsername : username, authenticationPassword : password};
            BOOL found = NO;
            for (NSUInteger i=0; i < previousAuthentications.count; i++) {
                NSDictionary *previousAuthentication = previousAuthentications[i];
                if ([[previousAuthentication objectForKey:authenticationHost] isEqualToString:host]) {
                    previousAuthentications[i] = newAuthentication;
                    found = YES;
                    break;
                }
            }
            if (!found) {
                [previousAuthentications addObject:newAuthentication];
            }
            _pendingChallenge = nil;
            _pendingChallengeCompletionHandler(NSURLSessionAuthChallengeUseCredential, newCredential);
            _pendingChallengeCompletionHandler = nil;
            return;
        } else if (returnCode == SEBEnterPasswordCancel) {
            _pendingChallenge = nil;
            _pendingChallengeCompletionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            _pendingChallengeCompletionHandler = nil;
        } else {
            // Any other case as when the server aborted the authentication challenge
            // We still might have to call the completion handler with the NSURLSessionAuthChallengeCancelAuthenticationChallenge answer
            _pendingChallenge = nil;
            _pendingChallengeCompletionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            _pendingChallengeCompletionHandler = nil;
            _authenticatingProtocol = nil;
        }
        [_delegate openingConfigURLRoleBack];
    }
}


- (NSDictionary *)fetchPreviousAuthenticationForHost:(NSString *)host
{
    NSString *predicateString = [[NSString stringWithFormat:@"%@ contains[c] ", authenticationHost] stringByAppendingString:@"%@"];
    NSPredicate *predicate = [NSPredicate predicateWithFormat:predicateString, host];
    NSArray *results = [previousAuthentications filteredArrayUsingPredicate:predicate];
    if (results.count == 1) {
        return results[0];
    } else {
        return nil;
    }
}


- (void)customHTTPProtocol:(CustomHTTPProtocol *)protocol didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    DDLogWarn(@"%s", __FUNCTION__);
    [_delegate hideEnterUsernamePasswordDialog];
}


#pragma mark - Downloading SEB Config Files

/// Initiating Opening the Config File Link

// Conditionally open a config from an URL passed to SEB as parameter
// usually with a link using the seb(s):// protocols
- (void) openConfigFromSEBURL:(NSURL *)url
{
    DDLogDebug(@"[SEBBrowserController openConfigFromSEBURL: %@]", url);
    if (!self.finishedInitializing) {
        // Wait until this SEBBrowserController finished initializing and then open this SEB URL
        DDLogDebug(@"[SEBBrowserController openConfigFromSEBURL:] Wait until this SEBBrowserController finished initializing and then open this SEB URL.");
        self.openConfigSEBURL = url;
    } else {
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        // Check first if opening SEB config files is allowed in settings and if no other settings are currently being opened
        if (!_downloadingInTemporaryWebView) {
            if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_downloadAndOpenSebConfig"]) {
                // Check if reconfiguring is actually allowed
                if (_delegate.startingUp || [self isReconfiguringAllowedFromURL:url]) {
                    // SEB isn't in exam mode: reconfiguring is allowed
                    NSURL *sebURL = url;
                    // Figure the download URL out, depending on if http or https should be used
                    url = [url URLByReplacingSEBScheme];
                    
                    void (^conditionallyDownloadConfig)(void) = ^void() {
                        // Check if we should try to download the config file from the seb(s) URL directly
                        // This is the case when the URL has a .seb filename extension
                        // But we only try it when it didn't fail in a first attempt
                        if (self.directConfigDownloadAttempted == NO) {
                            self.directConfigDownloadAttempted = YES;
                            self.originalURL = sebURL;
                            [self downloadSEBConfigFileFromURL:url originalURL:sebURL cookies:@[] sender:nil];
                        } else {
                            self.directConfigDownloadAttempted = NO;
                            self.downloadingInTemporaryWebView = YES;
                            self.temporaryWebView = [self.delegate openTempWebViewForDownloadingConfigFromURL:url originalURL:self.originalURL];
                        }
                    };

                    // When the URL of the SEB config file to load is on another host than the current page
                    // then we might need to clear session cookies before attempting to download the config file
                    // when the setting examSessionClearCookiesOnEnd is true
                    if (_delegate.currentMainHost && ![url.host isEqualToString:_delegate.currentMainHost]) {
                        // Set the flag for cookies cleared (either they actually will be or they would have
                        // been, but settings prevented it)
                        examSessionCookiesAlreadyCleared = YES;
                        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_examSessionClearCookiesOnEnd"]) {
                            // Empties all cookies, caches and credential stores, removes disk files, flushes in-progress
                            // downloads to disk, and ensures that future requests occur on a new socket.
                            DDLogInfo(@"-[SEBBrowserController openConfigFromSEBURL:] Cookies, caches and credential stores are being reset when ending browser session (examSessionClearCookiesOnEnd = true)");
                            [self resetAllCookiesWithCompletionHandler:^{
                                conditionallyDownloadConfig();
                            }];
                            return;
                        }
                    } else if (!_delegate.currentMainHost) {
                        // When currentMainHost isn't set yet, SEB was started with a config link, possibly
                        // to an authenticated server. In this case, session cookies shouldn't be cleared after logging in
                        // as they were anyways cleared when SEB was started
                        examSessionCookiesAlreadyCleared = YES;
                    }
                    [self transferCookiesToWKWebViewWithCompletionHandler:conditionallyDownloadConfig];
                    return;
                }
            } else {
                [_delegate showAlertNotAllowedDownloadingAndOpeningSebConfig:YES];
            }
        }
        DDLogDebug(@"%s aborted,%@%@", __FUNCTION__, [preferences secureBoolForKey:@"org_safeexambrowser_SEB_downloadAndOpenSebConfig"] == NO ? @" downloading and opening settings not allowed. " : @"", _temporaryWebView ? @" temporary webview already open" : @"");
        [_delegate openingConfigURLRoleBack];
    }
}


// Try to download the config by opening the URL in the temporary browser window
- (void) tryToDownloadConfigByOpeningURL:(NSURL *)url
{
    DDLogInfo(@"Loading SEB config from URL %@ in temporary browser window.", [url absoluteString]);
    [_temporaryWebView loadURL:url];
    
}


// Called by the browser webview delegate if loading the config URL failed
- (void) openingConfigURLFailed {
    DDLogDebug(@"%s", __FUNCTION__);
    
    // Close the temporary browser window if it was opened
    if (_temporaryWebView) {
        dispatch_async(dispatch_get_main_queue(), ^{
            DDLogDebug(@"Closing temporary browser window in: %s", __FUNCTION__);
            self.downloadingInTemporaryWebView = NO;
            [self.delegate closeWebView:self.temporaryWebView];
        });
    }
    
    [_delegate openingConfigURLRoleBack];
    
    // Also reset the flag for SEB starting up
    _delegate.startingUp = false;
}


/// Performing the Download

// This method is called by the browser webview delegate if the file to download has a .seb extension
- (void) downloadSEBConfigFileFromURL:(NSURL *)url originalURL:(NSURL *)originalURL cookies:(NSArray <NSHTTPCookie *>*)cookies sender:(nullable id<SEBAbstractBrowserControllerDelegate>)sender
{
    DDLogDebug(@"%s URL: %@", __FUNCTION__, url);
    
    NSString *scheme = url.scheme;
    NSString *host = url.host;
    NSString *resouceSpecifier = url.resourceSpecifier;
    DDLogDebug(@"Scheme: %@, host: %@, resource specifier: %@", scheme, host, resouceSpecifier);

    startURLQueryParameter = [self startURLQueryParameter:&url];
    
    // Use modern NSURLSession for downloading .seb files which also allows handling
    // basic/digest/NTLM authentication without having to open a temporary webview
    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration defaultSessionConfiguration];
    _URLSession = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:nil];
    NSURLSessionDataTask *downloadTask = [_URLSession dataTaskWithURL:url
                                                    completionHandler:^(NSData *sebFileData, NSURLResponse *response, NSError *error) {
        [self didDownloadConfigData:sebFileData response:response error:error URL:url originalURL:originalURL sender:sender];
    }];
    if (cookies.count > 0) {
        [sessionConfig.HTTPCookieStorage storeCookies:cookies forTask:downloadTask];
        NSHTTPCookieStorage *sessionCookieStore = sessionConfig.HTTPCookieStorage;
        DDLogVerbose(@"sessionCookieStore.cookies: %@", sessionCookieStore.cookies);
        [downloadTask resume];
    } else {
        if (@available(macOS 10.13, *)) {
            WKHTTPCookieStore *cookieStore = self.wkWebViewConfiguration.websiteDataStore.httpCookieStore;
            [cookieStore getAllCookies:^(NSArray<NSHTTPCookie *> * _Nonnull cookies) {
                [sessionConfig.HTTPCookieStorage storeCookies:cookies forTask:downloadTask];
                NSHTTPCookieStorage *sessionCookieStore = sessionConfig.HTTPCookieStorage;
                DDLogVerbose(@"sessionCookieStore.cookies: %@", sessionCookieStore.cookies);
                [downloadTask resume];
            }];
        } else {
            [downloadTask resume];
        }
    }
}


- (void) didDownloadConfigData:(NSData *)sebFileData
                      response:(NSURLResponse *)response
                         error:(NSError *)error
                           URL:(NSURL *)url
                   originalURL:(NSURL *)originalURL
                        sender:(nonnull id<SEBAbstractBrowserControllerDelegate>)sender
{
    DDLogDebug(@"-[SEBBrowserController didDownloadConfigData:response:error:URL:originalURL:] URL: %@, error: %@", url, error);
    if (sender) {
        [sender stopLoading];
        sender.downloadingSEBConfig = NO;
    }
    if (error) {
        if (error.code == NSURLErrorCancelled) {
            // Only close temp browser window if this wasn't a direct download attempt
            if (!_directConfigDownloadAttempted) {
                // Close the temporary browser window
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.downloadingInTemporaryWebView = NO;
                    [self.delegate closeWebView:self.temporaryWebView];
                });
                [_delegate openingConfigURLRoleBack];
                
            } else {
                _directConfigDownloadAttempted = false;
            }
            return;
        }
        if ([url.scheme isEqualToString:@"http"] && !_usingCustomURLProtocol) {
            // If it was a seb:// URL, and http failed, we try to download it by https
            NSURL *downloadURL = [url URLByReplacingScheme:@"https"];
            if (_directConfigDownloadAttempted) {
                [self downloadSEBConfigFileFromURL:downloadURL originalURL:originalURL cookies:@[] sender:sender];
            } else {
                [self tryToDownloadConfigByOpeningURL:downloadURL];
            }
        } else {
            if (_directConfigDownloadAttempted) {
                // If we tried a direct download first, now try to download it
                // by opening the URL in a temporary webview
                dispatch_async(dispatch_get_main_queue(), ^{
                    // which needs to be done on the main thread!
                    self.downloadingInTemporaryWebView = YES;
                    self.temporaryWebView = [self.delegate openTempWebViewForDownloadingConfigFromURL:url originalURL:originalURL];
                    self.temporaryWebView.originalURL = originalURL;
                });
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self downloadingSEBConfigFailed:error];
                });
            }
        }
    } else {
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        NSInteger statusCode = httpResponse.statusCode;
        DDLogDebug(@"NSHTTPURLResponse statusCode: %ld", (long)statusCode);

        dispatch_async(dispatch_get_main_queue(), ^{
            [self processDownloadedSEBConfigData:sebFileData fromURL:url originalURL:originalURL];
        });
    }
}


#pragma mark Downloading Files

- (void) downloadFileFromURL:(NSURL *)url
                    filename:(NSString *)filename
                     cookies:(NSArray <NSHTTPCookie *>*)cookies
                      sender:(nullable id<SEBAbstractBrowserControllerDelegate>)sender
{
    DDLogDebug(@"%s URL: %@", __FUNCTION__, url);
    
    NSURLSessionConfiguration *sessionConfig;
    if (!_URLSession) {
        sessionConfig = [NSURLSessionConfiguration defaultSessionConfiguration];
        _URLSession = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:nil];
    } else {
        sessionConfig = _URLSession.configuration;
    }
    NSURLSessionDownloadTask *downloadTask = [_URLSession downloadTaskWithURL:url
                                                            completionHandler:^(NSURL *fileLocation, NSURLResponse *response, NSError *error) {
        if (sender) {
            [sender stopLoading];
        }
        [self didDownloadFile:fileLocation filename:(NSString *)filename response:response error:error];
    }];
    [sessionConfig.HTTPCookieStorage storeCookies:cookies forTask:downloadTask];
    NSHTTPCookieStorage *sessionCookieStore = sessionConfig.HTTPCookieStorage;
    DDLogDebug(@"sessionCookieStore.cookies: %@", sessionCookieStore.cookies);
    [downloadTask resume];
}


- (void) didDownloadFile:(NSURL *)url
                filename:(NSString *)filename
                response:(NSURLResponse *)response
                   error:(NSError *)error
{
    NSString *suggestedFilename = response.suggestedFilename;
    NSURL *responseURL = response.URL;
    NSString *pathExtension = responseURL.pathExtension;
    DDLogDebug(@"%s from URL: %@ (NSURLResponse URL: %@), filename: %@, suggestedFilename: %@, error: %@", __FUNCTION__, url, responseURL, filename, suggestedFilename, error);
    
    if (!error) {
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    
        if (suggestedFilename.length == 0) {
            suggestedFilename = NSLocalizedString(@"Untitled", @"untitled filename");
        }
        
        // If we got the filename from a <a download="... tag, we use that
        // as older versions of WebKit don't recognize the filename and suggest "Unknown"
        if (filename.length > 0) {
            // If the filename consists only of a file extension
            if (filename.pathExtension.length == filename.length+1) {
                filename = [suggestedFilename stringByAppendingPathExtension:filename.pathExtension];
            }
        } else {
            // If we didn't get the file name, at least try to set the file extension properly
            filename = suggestedFilename;
        }

        if ((pathExtension && [pathExtension caseInsensitiveCompare:SEBFileExtension] == NSOrderedSame) ||
            (filename.pathExtension && [filename.pathExtension caseInsensitiveCompare:SEBFileExtension] == NSOrderedSame)) {
            // If file extension indicates a .seb file, we try to open it
            // First check if opening SEB config files is allowed in settings and if no other settings are currently being opened
            if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_downloadAndOpenSebConfig"]) {
                // Read the contents of the .seb config file and delete it from disk
                NSData *sebFileData = [NSData dataWithContentsOfURL:url];
                NSFileManager *fileManager = [NSFileManager defaultManager];
                [fileManager removeItemAtURL:url error:&error];
                if (error) {
                    DDLogError(@"Failed to remove downloaded SEB config file %@! Error: %@", url, [error userInfo]);
                }
                if (sebFileData) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [self processDownloadedSEBConfigData:sebFileData fromURL:url originalURL:nil];
                    });
                    return;
                }
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self.delegate showAlertNotAllowedDownloadingAndOpeningSebConfig:YES];
                });
                return;
            }
        } else if (self.allowDownloads) {
            // If downloading is allowed
            NSFileManager *fileManager = [NSFileManager defaultManager];
            int fileIndex = 1;
            NSURL *directory = self.downloadPathURL;
            NSString* filenameWithoutExtension = [filename stringByDeletingPathExtension];
            NSString* extension = [filename pathExtension];

            while ([fileManager moveItemAtURL:url toURL:[directory URLByAppendingPathComponent:filename isDirectory:NO] error:&error] == NO) {
                if (error.code == NSFileWriteFileExistsError) {
                    error = nil;
                    filename = [NSString stringWithFormat:@"%@-%d.%@", filenameWithoutExtension, fileIndex, extension];
                    fileIndex++;
                } else {
                    break;
                }
            }
            if (!error) {
                dispatch_async(dispatch_get_main_queue(), ^{
#if TARGET_OS_OSX
                    [self fileDownloadedSuccessfully:[directory URLByAppendingPathComponent:filename].path];
#else
                    [self fileDownloadedSuccessfully:filename];
#endif
                });
                return;
            } else {
                DDLogError(@"Failed to move downloaded file! %@", [error userInfo]);
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSError *downloadError = [NSError errorWithDomain:error.domain
                                                         code:error.code
                                                     userInfo:@{NSLocalizedDescriptionKey : NSLocalizedString(@"Failed to Save Downloaded File", @""),
                                                                NSLocalizedFailureReasonErrorKey : error.localizedDescription}];

                    [self.delegate presentDownloadError:downloadError];
                });
                return;
            }
        } else {
            // Downloading not allowed
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.delegate showAlertNotAllowedDownUploading:NO];
            });
            return;
        }
    }
    
    // Download failed: Show error message
    DDLogError(@"Download failed! Error - %@ %@",
               error.description,
               [error.userInfo objectForKey:NSURLErrorFailingURLStringErrorKey]);
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate presentDownloadError:error];
    });
}


- (NSURL *) downloadPathURL
{
    return downloadDirectoryURL;
}


- (void) storeDownloadPath:(NSString *)path
{
    NSMutableArray *downloadPaths = [NSMutableArray arrayWithArray:[[MyGlobals sharedMyGlobals] downloadPath]];
    if (!downloadPaths) {
        downloadPaths = [NSMutableArray arrayWithCapacity:1];
    }
    [downloadPaths addObject:path];
    [[MyGlobals sharedMyGlobals] setDownloadPath:downloadPaths];
    [[MyGlobals sharedMyGlobals] setLastDownloadPath:[downloadPaths count]-1];
}


- (void) fileDownloadedSuccessfully:(NSString *)path
{
    DDLogInfo(@"Download of File %@ did finish.", path);
    [self storeDownloadPath:path];
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    NSString *pathExtension = path.pathExtension;
    NSURL *downloadedFileURL = [NSURL fileURLWithPath:path];
    if (((pathExtension && [pathExtension caseInsensitiveCompare:filenameExtensionPDF] == NSOrderedSame) && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_downloadPDFFiles"]) ||
        [preferences secureBoolForKey:@"org_safeexambrowser_SEB_openDownloads"]) {
        // Open downloaded file
        NSString *bundleId = [AdditionalApplicationsController appBundleIdentifierWithFileExtension:pathExtension];
        if (bundleId) {
            NSString *appScheme = [AdditionalApplicationsController appSchemeWithBundleIdentifier:bundleId];
            if (appScheme) {
                DDLogInfo(@"Custom protocol scheme %@ is configured for downloaded file.", appScheme);
                downloadedFileURL = [downloadedFileURL URLByReplacingScheme:appScheme];
                DDLogInfo(@"URL using custom protocol scheme: %@", downloadedFileURL);
            } else {
                if ([self.delegate respondsToSelector:@selector(openDownloadedFile:withAppBundleId:)]) {
                    [self.delegate openDownloadedFile:downloadedFileURL withAppBundleId:bundleId];
                    return;
                }
            }
        }
        if ([self.delegate respondsToSelector:@selector(openDownloadedFile:)]) {
            [self.delegate openDownloadedFile:downloadedFileURL];
            return;
        }
    }
    [self.delegate presentAlertWithTitle:NSLocalizedString(@"Download Finished", @"")
                                 message:[NSString stringWithFormat:NSLocalizedString(@"Saved file '%@'", @""), path.lastPathComponent]];
}


- (void)webView:(WKWebView *)webView
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    DDLogVerbose(@"WKWebView: %@ didReceiveAuthenticationChallenge: %@", webView, challenge);
    [self didReceiveAuthenticationChallenge:challenge completionHandler:completionHandler];
}

// NSURLSession download basic/digest/NTLM authentication challenge delegate
// Only called when downloading (.seb) files
- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    DDLogDebug(@"URLSession: %@ task: %@ didReceiveChallenge: %@", session, task, challenge);
    [self didReceiveAuthenticationChallenge:challenge completionHandler:completionHandler];
}

- (void)didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    // Check if we deal with a username/password or a server trust authentication challenge
    NSString *authenticationMethod = challenge.protectionSpace.authenticationMethod;
    if ([authenticationMethod isEqual:NSURLAuthenticationMethodHTTPBasic] ||
        [authenticationMethod isEqual:NSURLAuthenticationMethodHTTPDigest] ||
        [authenticationMethod isEqual:NSURLAuthenticationMethodNTLM])
    {
        DDLogDebug(@"%s: authentication challenge method: %@", __FUNCTION__, authenticationMethod);
#if DEBUG
        NSString *server = [NSString stringWithFormat:@"%@://%@", challenge.protectionSpace.protocol, challenge.protectionSpace.host];
        DDLogDebug(@"Server which requires authentication: %@", server);
#endif
        if (_pendingChallenge) {
            // There already is a pending challenge: We cancel the current one expecting a new one will be created
            // at a later point, when the pending one maybe already was processed
            // ToDo: Maybe allow parallel challenges to be processes in future
            DDLogWarn(@"Canceling new authentication challenge as there is already a pending challenge");
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        } else {
            _pendingChallenge = challenge;
            
            NSString *host = challenge.protectionSpace.host;
            NSDictionary *previousAuthentication = [self fetchPreviousAuthenticationForHost:host];
            if (!_pendingChallengeCompletionHandler && previousAuthentication && challenge.previousFailureCount == 0) {
                NSURLCredential *newCredential;
                newCredential = [NSURLCredential credentialWithUser:[previousAuthentication objectForKey:authenticationUsername]
                                                           password:[previousAuthentication objectForKey:authenticationPassword]
                                                        persistence:NSURLCredentialPersistenceForSession];
                completionHandler(NSURLSessionAuthChallengeUseCredential, newCredential);
                _pendingChallenge = nil;
                return;
            }
            // Allow to enter password 3 times
            if ([challenge previousFailureCount] < 3) {
                // Display authentication dialog
                _pendingChallengeCompletionHandler = completionHandler;
                
                NSString *text = [self urlPlaceholderTitleForWebpage];
                if (!text) {
                    text = [NSString stringWithFormat:@"%@://%@", challenge.protectionSpace.protocol, host];
                } else {
                    if ([challenge.protectionSpace.protocol isEqualToString:@"https"]) {
                        text = [NSString stringWithFormat:@"%@ (secure connection)", text];
                    } else {
                        text = [NSString stringWithFormat:@"%@ (insecure connection!)", text];
                    }
                }
                if ([challenge previousFailureCount] == 0) {
                    text = [NSString stringWithFormat:@"%@ %@", NSLocalizedString(@"Log in to", @""), text];
                    _lastUsername = @"";
                } else {
                    text = [NSString stringWithFormat:NSLocalizedString(@"The user name or password for %@ was incorrect. Please try again.", @""), text];
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self.delegate showEnterUsernamePasswordDialog:text
                                                             title:NSLocalizedString(@"Authentication Required", @"")
                                                          username:self.lastUsername
                                                     modalDelegate:self
                                                    didEndSelector:@selector(enteredUsername:password:returnCode:)];
                });
                
            } else {
                completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
                _pendingChallenge = nil;
                // inform the user that the user name and password
                // in the preferences are incorrect
                [_delegate openingConfigURLRoleBack];
            }
        }
        
    } else {
        // Server trust authentication challenge
        if (!usingEmbeddedCertificates) {
            DDLogVerbose(@"DidReceive other authentication challenge, not using embedded certificates: Default handling");
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
        } else {
            BOOL authorized = NO;
            NSURLCredential *credential;
            SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
            NSString *serverHost = challenge.protectionSpace.host;
            NSInteger serverPort = challenge.protectionSpace.port;

            if (serverTrust)
            {
                SEBCertServices *sc = [SEBCertServices sharedInstance];
                
                NSArray *trustStore = nil;
                NSMutableArray *embeddedCertificates = [NSMutableArray arrayWithArray:[sc caCerts]];
                
                if (!pinEmbeddedCertificates)
                {
                    // Embedded SSL/TLS certs extend system trust store if
                    // not pinned (these would typically be self-signed)
                    [embeddedCertificates addObjectsFromArray:[sc tlsCerts]];
                    
                    // Also add embedded debug certs, which we also use to extend
                    // the system trust store (note: they might fail the first check
                    // because of expiration or common name/alternative names not
                    // matching domain
                    [embeddedCertificates addObjectsFromArray:[sc debugCerts]];
                }
                
                if (pinEmbeddedCertificates || [embeddedCertificates count])
                {
                    trustStore = embeddedCertificates;
                }
                
                // If pinned, only embedded CA certs will be in trust store
                // If !pinned, system trust store is extended by embedded CA and SSL/TLS (including debug) certs
                SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)trustStore); // If trustStore == nil, use system default
                SecTrustSetAnchorCertificatesOnly(serverTrust, pinEmbeddedCertificates);
                
                SecTrustResultType result;
                OSStatus status = SecTrustEvaluate(serverTrust, &result);
                
    #if DEBUG
                DDLogDebug(@"Server host: %@ and port: %ld", serverHost, (long)serverPort);
    #endif

                if (status == errSecSuccess && (result == kSecTrustResultProceed || result == kSecTrustResultUnspecified))
                {
                    authorized = YES;
                    if (![authorizedHosts containsObject:serverHost]) {
                        [authorizedHosts addObject:serverHost];
                    }
                    
                } else {
                    // Because the CA trust evaluation above failed, we know that the
                    // server's SSL/TLS cert does not chain back to a CA root cert from
                    // any embedded CA root certs (or if it did, it was deemed invalid
                    // on other grounds such as expiration, or required private
                    // intermediate CA certs were not included in caCerts)
                    //
                    // We now need to explicitly handle the case of the user wanting to
                    // pin a (usually self-signed) SSL/TLS cert or use a debug cert which
                    // can be expired or issued for another server domain (in the debug case
                    // we check if the server domain matches the debug cert's "name" field.
                    // For this check, we must have
                    // an embedded SSL/TLS cert whose public key matches the server's
                    // SSL/TLS cert (we compare against the public key because the
                    // server's cert could be re-issued with the same PK but with other
                    // differences)
                    
                    // First check if not authorized domain is
                    // a subdomain of a previously trused domain
                    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"%@ contains[c] SELF", serverHost];
                    NSArray *results = [authorizedHosts filteredArrayUsingPredicate:predicate];
                    if (results.count > 0) {
                        authorized = YES;
                    } else {
                        // Use embedded debug certs if some are available
                        embeddedCertificates = [NSMutableArray arrayWithArray:[sc debugCerts]];
                        NSInteger debugCertsCount = embeddedCertificates.count;
                        NSArray *debugCertNames = [sc debugCertNames];
                        
                        // Add regular TLS certs
                        [embeddedCertificates addObjectsFromArray:[sc tlsCerts]];
                        
                        if ([embeddedCertificates count])
                        {
                            // Index 0 (leaf) is always present
                            SecCertificateRef serverLeafCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
                            
                            if (serverLeafCertificate)
                            {
                                NSData *serverLeafCertificateDataDER = CFBridgingRelease(SecCertificateCopyData(serverLeafCertificate));
                                
                                if (serverLeafCertificateDataDER)
                                {
                                    mbedtls_x509_crt serverCert;
                                    mbedtls_x509_crt_init(&serverCert);
                                    
                                    if (mbedtls_x509_crt_parse_der(&serverCert, [serverLeafCertificateDataDER bytes], [serverLeafCertificateDataDER length]) == 0)
                                    {
    #if DEBUG
                                        char infoBuf[2048];
                                        *infoBuf = '\0';
                                        mbedtls_x509_crt_info(infoBuf, sizeof(infoBuf) - 1, "   ", &serverCert);
                                        DDLogDebug(@"Server leaf certificate:\n%s", infoBuf);
                                        [serverLeafCertificateDataDER writeToFile:[[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0]
                                                                                   stringByAppendingPathComponent:@"last_server.der"] atomically:YES];
    #endif
                                        unsigned char *pkBuffer;
                                        unsigned int pkBufferSize;
                                        
                                        // We're extracting the SPKI, not just the PK bit string.
                                        // This is an additional level of security. See here:
                                        // https://www.imperialviolet.org/2011/05/04/pinning.html
                                        mbedtls_x509_private_seb_obtainLastPublicKeyASN1Block(&pkBuffer, &pkBufferSize);
                                        
                                        unsigned int serverPkBufferSize = pkBufferSize;
                                        unsigned char *serverPkBuffer = malloc(serverPkBufferSize);
                                        
                                        if (serverPkBuffer)
                                        {
                                            memcpy(serverPkBuffer, pkBuffer, serverPkBufferSize);
                                            // Now we have the public key bytes in serverPkBuffer
                                            
                                            mbedtls_x509_crt tlsList;
                                            mbedtls_x509_crt_init(&tlsList);
                                            
                                            for (NSInteger i = 0; i < [embeddedCertificates count]; i++)
                                            {
                                                NSData *tlsData = CFBridgingRelease(SecCertificateCopyData((SecCertificateRef)[embeddedCertificates objectAtIndex:i]));
                                                
                                                if (tlsData)
                                                {
                                                    if (mbedtls_x509_crt_parse_der(&tlsList, [tlsData bytes], [tlsData length]) == 0)
                                                    {
                                                        mbedtls_x509_private_seb_obtainLastPublicKeyASN1Block(&pkBuffer, &pkBufferSize);
                                                        
                                                        if (serverPkBufferSize == pkBufferSize)
                                                        {
                                                            if (memcmp(serverPkBuffer, pkBuffer, serverPkBufferSize) == 0)
                                                            {
                                                                // We have an exact PK match with the server cert which
                                                                // means that we trust this server because it must have
                                                                // the associated private key to decrypt traffic sent
                                                                // to it. All that remains to be done is basic validation
                                                                // such as domain and expiration checks which we let the
                                                                // OS handle by evaluating a custom trust store.
                                                                NSArray *array = [NSArray arrayWithObject:[embeddedCertificates objectAtIndex:i]];
                                                                SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)array);
                                                                status = SecTrustEvaluate(serverTrust, &result);
                                                                
                                                                if (status == errSecSuccess && (result == kSecTrustResultProceed || result == kSecTrustResultUnspecified))
                                                                {
                                                                    authorized = YES;
                                                                    // If the cert didn't pass this basic validation
                                                                } else if (i < debugCertsCount) {
                                                                    // and it is a debug cert, check if server domain (host:port) matches the "name" subkey of this embedded debug cert
                                                                    NSString *debugCertOverrideURLString = debugCertNames[i];
                                                                    
                                                                    // Check if filter expression contains a scheme
                                                                    if (debugCertOverrideURLString.length > 0) {
                                                                        // We can abort if there is no override domain for the cert
                                                                        NSRange scanResult = [debugCertOverrideURLString rangeOfString:@"://"];
                                                                        if (scanResult.location == NSNotFound) {
                                                                            // Filter expression doesn't contain a scheme, prefix it with a https:// scheme
                                                                            debugCertOverrideURLString = [NSString stringWithFormat:@"https://%@", debugCertOverrideURLString];
                                                                            // Convert override domain string to a NSURL
                                                                        }
                                                                        NSURL *debugCertOverrideURL = [NSURL URLWithString:debugCertOverrideURLString];
                                                                        if (debugCertOverrideURL) {
                                                                            // If certificate doesn't have any correct override domain in its name field, abort
                                                                            NSString *certHost = debugCertOverrideURL.host;
                                                                            NSNumber *certPort = debugCertOverrideURL.port;
    #if DEBUG
                                                                            DDLogDebug(@"Cert host: %@ and port: %@", certHost, certPort);
    #endif
                                                                            NSPredicate *predicate = [NSPredicate predicateWithFormat:@"self LIKE %@", certHost];
                                                                            if ([predicate evaluateWithObject:serverHost]) {
                                                                                // If the server host name matches the one in the debug cert ...
                                                                                if (!certPort || certPort.integerValue == serverPort) {
                                                                                    // ... and there either is not port indicated in the cert
                                                                                    // or it is same as the one of the server we're connecting to, we accept it
                                                                                    authorized = YES;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            
                                            mbedtls_x509_crt_free(&tlsList);
                                            free(serverPkBuffer);
                                        }
                                    }
                                    
                                    mbedtls_x509_crt_free(&serverCert);
                                }
                            }
                        }
                    }
                }
            }
            if (authorized)
            {
                DDLogDebug(@"%s: didReceiveAuthenticationChallenge", __FUNCTION__);
                
                credential = [NSURLCredential credentialForTrust:serverTrust];
                completionHandler(NSURLSessionAuthChallengeUseCredential, credential);

            } else {

                DDLogWarn(@"%s: didCancelAuthenticationChallenge for host: %@ and port: %ld", __FUNCTION__, serverHost, (long)serverPort);

                // [R1-5] A rejected TLS trust evaluation for OUR OWN server during a home session is
                // the 3 Aug incident's exact signature (an intercepting network forging the cert).
                // The resulting load failure often surfaces to WebKit as a CANCELLED provisional
                // navigation (−999), which sebWebViewDidFailLoadWithError: swallows — so the offline
                // panel must be triggered from HERE, where we know it's a TLS-trust failure. The
                // observer (SEBController) gates on an active home session; kind=cert adds the
                // "this network appears to be inspecting secure traffic" sentence.
                if (serverHost.length &&
                    ([serverHost isEqualToString:@"blinkered.com.au"] || [serverHost hasSuffix:@".blinkered.com.au"])) {
                    [[NSNotificationCenter defaultCenter] postNotificationName:@"blinkeredHomeConnectivityFailed"
                                                                        object:self
                                                                      userInfo:@{ @"kind": @"cert", @"host": serverHost }];
                }

                completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
                // If SEB was starting up, then a roleback is necessary
                [_delegate openingConfigURLRoleBack];
            }
        }
    }
}


// Managing entered credentials for .seb file download
- (void)enteredURLSessionUsername:(NSString *)username password:(NSString *)password returnCode:(NSInteger)returnCode
{
    DDLogDebug(@"Enter username password sheetDidEnd with return code: %ld", (long)returnCode);
    
    if (_pendingChallengeCompletionHandler) {
        if (returnCode == SEBEnterPasswordOK) {
            _lastUsername = username;
            NSURLCredential *newCredential = [NSURLCredential credentialWithUser:username
                                                                        password:password
                                                                     persistence:NSURLCredentialPersistenceForSession];
            _pendingChallengeCompletionHandler(NSURLSessionAuthChallengeUseCredential, newCredential);
            
            _enteredCredential = newCredential;
            return;
            
            // Authentication wasn't successful
        } else if (returnCode == SEBEnterPasswordCancel) {
            _pendingChallengeCompletionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            _enteredCredential = nil;
            _pendingChallengeCompletionHandler = nil;
        } else {
            // Any other case as when the server aborted the authentication challenge
            _enteredCredential = nil;
            _pendingChallengeCompletionHandler = nil;
        }
        [_delegate openingConfigURLRoleBack];
    }
}


// Called when downloading the config file failed
- (void) downloadingSEBConfigFailed:(NSError *)error
{
    DDLogError(@"%s error: %@", __FUNCTION__, error);
    [_delegate downloadingSEBConfigFailed:error];
}


// Called when SEB successfully downloaded the config file
- (void) processDownloadedSEBConfigData:(NSData *)sebFileData fromURL:(NSURL *)url originalURL:(NSURL *)originalURL
{
    DDLogDebug(@"%s URL: %@", __FUNCTION__, url);
    
    // Close the temporary browser window
    if (_temporaryWebView) {
        self.downloadingInTemporaryWebView = NO;
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.delegate closeWebView:self.temporaryWebView];
            self.temporaryWebView = nil;
            [self processDownloadedSEBConfigData:sebFileData fromURL:url originalURL:originalURL];
        });
        return;
    }
    
    // Reset the pending challenge in case it was an authenticated load
    _pendingChallengeCompletionHandler = nil;
    
    if (_delegate.startingUp || [self isReconfiguringAllowedFromURL:originalURL ? originalURL : url]) {
        
        void (^completionHandler)(void) = ^void() {
            self->downloadedSEBConfigDataURL = url;
            [self.delegate openDownloadedSEBConfigData:sebFileData fromURL:url originalURL:originalURL];
        };
        
        if (examSessionCookiesAlreadyCleared == NO) {
            if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_examSessionClearCookiesOnEnd"] == YES) {
                // Empties all cookies, caches and credential stores, removes disk files, flushes in-progress
                // downloads to disk, and ensures that future requests occur on a new socket.
                DDLogInfo(@"-[SEBBrowserController processDownloadedSEBConfigData: fromURL: originalURL:] Cookies, caches and credential stores are being reset when ending browser session (examSessionClearCookiesOnEnd = true)");
                [self resetAllCookiesWithCompletionHandler:^{
                    completionHandler();
                }];
                return;
            }
            // Set the flag for cookies cleared (either they actually were or they would have
            // been settings prevented it)
            examSessionCookiesAlreadyCleared = YES;
        }
        [self transferCookiesToWKWebViewWithCompletionHandler:completionHandler];

    } else {
        // Opening downloaded SEB config data definitely failed:
        // we might need to quit (if SEB was just started)
        // or reset the opening settings flag which prevents opening URLs concurrently
        [_delegate openingConfigURLRoleBack];
    }
}


- (void) storeNewSEBSettingsSuccessful:(NSError *)error
{
    if (!error) {
        DDLogInfo(@"Storing downloaded SEB config data was successful");
        
        // Reset the direct download flag for the case this was a successful direct download
        _directConfigDownloadAttempted = NO;
        
        [[NSUserDefaults standardUserDefaults] setSecureString:startURLQueryParameter forKey:@"org_safeexambrowser_startURLQueryParameter"];
        
    } else {
        /// Decrypting new settings wasn't successfull:
        DDLogInfo(@"Decrypting downloaded SEB config data failed or data needs to be downloaded in a temporary WebView after the user performs web-based authentication.");
        
        // Was this an attempt to download the config directly and the downloaded data was corrupted?
        if (_directConfigDownloadAttempted && error.code == SEBErrorNoValidConfigData) {
            // We try to download the config in a temporary WebView
            DDLogInfo(@"Trying to download the config in a temporary WebView");
            [self openConfigFromSEBURL:downloadedSEBConfigDataURL];
            
            return;
        } else {
            // The download failed definitely or was canceled by the user:
            DDLogError(@"Decrypting downloaded SEB config data failed definitely, present error and role back opening URL!");
            
            // Reset the direct download flag for the case this was a successful direct download
            _directConfigDownloadAttempted = NO;
        }
    }
    [_delegate storeNewSEBSettingsSuccessfulProceed:error];
}


#pragma mark - Handling Universal Links

// Check if a URL is in an associated domain and therefore might have been
// invoked with a Universal Link
- (BOOL) isAssociatedDomain:(NSURL *)url
{
    if (![url.scheme isEqualToString:@"https"]) {
        // Universal Links must use the https protocol
        return NO;
    }
    NSString *entitlementsPath = [NSBundle.mainBundle pathForResource:[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleDisplayName"]
                                                     ofType:@"entitlements"];
    NSDictionary *entitlements = [[NSDictionary alloc]initWithContentsOfFile:entitlementsPath];
    NSArray *associatedDomains = [entitlements objectForKey:@"com.apple.developer.associated-domains"];
    NSString *host = url.host;
    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"SELF contains[c] %@", host];
    NSArray *results = [associatedDomains filteredArrayUsingPredicate:predicate];
    // The URLs host is contained in our associated domains
    return (results.count != 0);
}


// Tries to find SEBSettings.seb or SEBExamSettings.seb files stored at folders
// specified by a Universal Link
- (void) handleUniversalLink:(NSURL *)universalLink
{
    _didReconfigureWithUniversalLink = NO;
    _cancelReconfigureWithUniversalLink = NO;
    if (universalLink) {
        if ([[NSUserDefaults standardUserDefaults] secureBoolForKey:@"org_safeexambrowser_SEB_downloadAndOpenSebConfig"]) {
            // Remove query and fragment parts from the Universal Link URL
            NSURLComponents *urlComponents = [NSURLComponents componentsWithURL:universalLink resolvingAgainstBaseURL:NO];
            urlComponents.query = nil;
            urlComponents.fragment = nil;
            NSURL *urlWithPartialPath = urlComponents.URL;
            
            if (urlWithPartialPath.pathExtension.length != 0) {
                // If the path specified a file, remove it from the path as well
                urlWithPartialPath = [urlWithPartialPath URLByDeletingLastPathComponent];
            }
            
            // Check for a file called "SEBSettings.seb" recursivly in the
            // folder hierarchy specified by the original Universal Link
            [self downloadConfigFile:SEBSettingsFilename
                             fromURL:urlWithPartialPath
                   universalLinkHost:urlWithPartialPath
                       universalLink:universalLink];
        } else {
            [_delegate showAlertNotAllowedDownloadingAndOpeningSebConfig:YES];
        }
    }
}


// We didn't find valid SEB settings named configFileName in the
// folder hierarchy specified by the Universal Link
- (void) universalLinkNoConfigFile:(NSString *)configFileName
                            atHost:(NSURL *)host
                     universalLink:(NSURL *)universalLink
{
    if (configFileName && [configFileName caseInsensitiveCompare:SEBSettingsFilename] == NSOrderedSame) {
        // No "SEBSettings.seb" file found, search for "SEBExamSettings.seb" file
        // recursivly starting at the folder addressed by the original Universal Link
        [self downloadConfigFile:SEBExamSettingsFilename
                         fromURL:host
               universalLinkHost:host
                   universalLink:universalLink];
    } else {
        // Also no "SEBExamSettings.seb" file found, stop the search
        _downloadTask = nil;
        if (_isShowingOpeningConfigFileDialog) {
            [_delegate closeOpeningConfigFileDialog];
            _isShowingOpeningConfigFileDialog = NO;
        }
        NSError *error = nil;
        // If no valid client config was found (in the "SEBSettings.seb" file), return an error message
        if (_cancelReconfigureWithUniversalLink) {
            error = [[NSError alloc]
                        initWithDomain:sebErrorDomain
                        code:SEBErrorOpeningUniversalLinkFailed
                        userInfo:@{ NSLocalizedDescriptionKey : NSLocalizedString(@"Opening Universal Link Failed", @""),
                                    NSLocalizedRecoverySuggestionErrorKey : [NSString stringWithFormat:NSLocalizedString(@"Searching for a valid %@ config file was canceled.", @""), SEBShortAppName],
                                    }];
        } else if (!_didReconfigureWithUniversalLink) {
            error = [[NSError alloc]
                     initWithDomain:sebErrorDomain
                     code:SEBErrorOpeningUniversalLinkFailed
                     userInfo:@{ NSLocalizedDescriptionKey : NSLocalizedString(@"Opening Universal Link Failed", @""),
                                 NSLocalizedRecoverySuggestionErrorKey : [NSString stringWithFormat:NSLocalizedString(@"No %@ settings have been found at the specified URL. Use a correct link to configure %@ or start an exam.", @""), SEBShortAppName, SEBShortAppName],
                                 }];
        }

        [_delegate storeNewSEBSettingsSuccessfulProceed:error];
    }
}

// Try to recursivly find SEB settings named configFileName starting at the path in universalLinkHost
// the current path to look for the config file is specified in fromURL
- (void) downloadConfigFile:(NSString *)configFileName
                    fromURL:(NSURL *)url
          universalLinkHost:(NSURL *)host
              universalLink:(NSURL *)universalLink
{
    if (url.path.length == 0 || _cancelReconfigureWithUniversalLink) {
        // Searched the full subdirectory hierarchy of this host address
        [self universalLinkNoConfigFile:configFileName
                                 atHost:host
                          universalLink:universalLink];
    } else {
        if (!_isShowingOpeningConfigFileDialog) {
            [_delegate showOpeningConfigFileDialog:[NSString stringWithFormat:NSLocalizedString(@"Searching for a valid %@ config file …", @""), SEBShortAppName]
                                             title:NSLocalizedString(@"Opening Universal Link", @"")
                                    cancelCallback:self
                                          selector:@selector(cancelDownloadingConfigFile)];
            _isShowingOpeningConfigFileDialog = YES;
        }

        NSURL *newURL = url;
        // Remove the last path component or the trailing slash "/" from the
        // URL we're currently trying to download the config file
        if (![url.lastPathComponent isEqualToString:@"/"]) {
            newURL = [url URLByDeletingLastPathComponent];
        } else {
            NSURLComponents *urlComponents = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            urlComponents.path = nil;
            newURL = urlComponents.URL;
        }
        url = [url URLByAppendingPathComponent:configFileName];
        
        if (!_URLSession) {
            NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration defaultSessionConfiguration];
            _URLSession = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:nil];
        }
        _downloadTask = [_URLSession dataTaskWithURL:url
                                   completionHandler:^(NSData *sebFileData, NSURLResponse *response, NSError *error)
                         {
                             [self didDownloadData:sebFileData
                                        configFile:configFileName
                                 universalLinkHost:host
                                     universalLink:universalLink
                                             error:error
                                               URL:newURL];
                         }];
        [_downloadTask resume];
    }
}


// Callback for trying to download SEB config file recursivly from hierarchy
// of subdirectories specified by universalLinkHost
- (void) didDownloadData:(NSData *)sebFileData
              configFile:(NSString *)fileName
       universalLinkHost:(NSURL *)host
           universalLink:(NSURL *)universalLink
                   error:(NSError *)error
                     URL:(NSURL *)url
{
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_downloadTask = nil;
        
        if (error || !sebFileData || self->_cancelReconfigureWithUniversalLink) {
            // Couldn't download config file, try it one level down in the path hierarchy
            [self downloadConfigFile:fileName
                             fromURL:url
                   universalLinkHost:host
                       universalLink:universalLink];
        } else {
            // Successfully downloaded SEB settings file or some other HTML data like a
            // 404 http page not found error webpage, therefore we have to check if
            // we downloaded correct SEB settings
            
            // The dialog for opening the config file needs to be closed to prevent
            // issues when another alert is presented in the store method
            if (self->_isShowingOpeningConfigFileDialog) {
                [self->_delegate closeOpeningConfigFileDialog];
                self->_isShowingOpeningConfigFileDialog = NO;
            }

            self->cachedConfigFileName = fileName;
            self->cachedDownloadURL = url;
            self->cachedHostURL = host;
            self->cachedUniversalLink = universalLink;
            [self->_delegate storeNewSEBSettings:sebFileData
                                forEditing:NO
                    forceConfiguringClient:NO
                     showReconfiguredAlert:NO
                                  callback:self
                                  selector:@selector(storeNewSEBSettingsFromUniversalLinkSuccessful:)];
        }
    });
}


// Cancel a processing download
- (void) cancelDownloadingConfigFile
{
    _cancelReconfigureWithUniversalLink = YES;
    if (_downloadTask) {
        [_downloadTask cancel];
        _downloadTask = nil;
    }
}


// Were correct SEB settings downloaded and sucessfully stored?
- (void) storeNewSEBSettingsFromUniversalLinkSuccessful:(NSError *)error
{
    if (error) {
        DDLogDebug(@"%s error: %@", __FUNCTION__, error);
        
        // Downloaded data was either no correct SEB config file
        // or this couldn't be stored (wrong passwords entered etc)
        [self downloadConfigFile:cachedConfigFileName
                         fromURL:cachedDownloadURL
               universalLinkHost:cachedHostURL
                   universalLink:cachedUniversalLink];
    } else {
        // Successfully found and stored some SEB settings
        // Store the file name of the .seb file as current config file path
        DDLogInfo(@"Storing downloaded SEB config data was successful");
        [[MyGlobals sharedMyGlobals] setCurrentConfigURL:[NSURL URLWithString:cachedConfigFileName]];

        // If these SEB settings came from
        // a "SEBSettings.seb" file, we check if they contained Client Settings
        if ((cachedConfigFileName && [cachedConfigFileName caseInsensitiveCompare:SEBSettingsFilename] == NSOrderedSame) &&
            ![NSUserDefaults userDefaultsPrivate]) {
            // SEB successfully read a SEBSettings.seb file with Client Settings
            // Now we try if there is a "SEBExamSettings.seb" file as well in the
            // same path hierarchy, as one Universal Link SEB can both configure/
            // reconfigure SEB Client Settings and start an exam
            _didReconfigureWithUniversalLink = YES;
            [self downloadConfigFile:SEBExamSettingsFilename
                             fromURL:cachedHostURL
                   universalLinkHost:cachedHostURL
                       universalLink:cachedUniversalLink];
        } else {
            // There either were Exam Settings in the SEBSettings.seb file
            // (no Client Settings), then we can stop searching further and
            // start the exam. Or we found Exam Settings in the
            // SEBExamSettings.seb file, then we can start that exam.
            if (_isShowingOpeningConfigFileDialog) {
                [_delegate closeOpeningConfigFileDialog];
                _isShowingOpeningConfigFileDialog = NO;
            }

            // Check if the Start URL Deep Link feature is allowed and store the
            // original full Universal Link as the deep link
            NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
            if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_startURLAllowDeepLink"]) {
                [preferences setSecureString:cachedUniversalLink.absoluteString
                                      forKey:@"org_safeexambrowser_startURLDeepLink"];
            }

            [_delegate storeNewSEBSettingsSuccessfulProceed:error];
        }
    }
}


#pragma mark - Blinkered session menu (home tab bar identity dropdown)

// A native session-menu item was picked — hand the id back to the page that requested the menu.
// The page (home-content.html) dispatches to the same handlers its DOM-dropdown fallback uses.
- (void)blinkeredSessionMenuPicked:(NSMenuItem *)sender
{
    NSDictionary *info = sender.representedObject;
    if (![info isKindOfClass:[NSDictionary class]]) return;
    NSString *itemId = info[@"id"];
    WKWebView *pageView = info[@"webView"];
    if (![itemId isKindOfClass:[NSString class]] || ![pageView isKindOfClass:[WKWebView class]]) return;
    // itemId came from the page's own showSessionMenu payload. The hand-rolled `\\` then `'`
    // escaping here was CORRECT — it was the model the two §0 sites should have copied — but it is
    // still a third convention in a file that grew three, two of them wrong. One helper, everywhere.
    NSString *js = [NSString stringWithFormat:@"window.__blinkeredMenuPick && window.__blinkeredMenuPick(%@)",
                    [SEBAbstractWebView blinkeredJSStringLiteral:itemId]];
    [pageView evaluateJavaScript:js completionHandler:nil];
}

// Semantic session-menu icon name (as posted by home-content.html's SESSION_MENU_ICON) → SF Symbol,
// so every native menu item carries the same glyph the Windows menu shows. Returns nil for an unknown
// name or (on an OS lacking the symbol) so the item simply renders without an icon.
- (NSImage *)blinkeredSessionMenuIconForName:(NSString *)name
{
    if (![name isKindOfClass:[NSString class]] || name.length == 0) return nil;
    static NSDictionary *map = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        map = @{ @"calendar": @"calendar",                            // My day
                 @"class":    @"graduationcap.fill",                  // Join / leave class
                 @"message":  @"message.fill",                        // Message parent
                 @"site":     @"globe",                               // Request a website
                 @"switch":   @"arrow.left.arrow.right",              // Switch user
                 @"exit":     @"rectangle.portrait.and.arrow.right" }; // Exit / leave
    });
    NSString *symbol = map[name];
    if (!symbol) return nil;
    if (@available(macOS 11.0, *)) {
        return [NSImage imageWithSystemSymbolName:symbol accessibilityDescription:nil];
    }
    return nil;
}


#pragma mark - Blinkered per-child cookie isolation (shared devices)

// Swap the cookie jar for a shared-device profile switch, then navigate. We use the WKHTTPCookie
// store (the same one SEB already manipulates) so no web view is recreated — the kiosk is never
// disturbed. On 'login' the restore completes BEFORE navigation, so the incoming child's session
// cookies are in place when their page loads.
- (void)blinkeredProfileSwitch:(NSString *)action childId:(NSString *)childId url:(NSString *)navUrl webView:(WKWebView *)webView
{
    if (![webView isKindOfClass:[WKWebView class]]) return;
    // Remember this child for the rest of the session: transferCookies (called on EVERY new window,
    // including the Alto popup) now restores THIS child's cookies instead of the global cookies.json,
    // and exitSEB saves to this child's file. Without this, SEB re-injected the previous kid's
    // cookies.json into the popup right after our wipe, leaking their logins.
    // A runtime (shared-device picker) login: use this child's jar, but NEVER migrate the legacy global jar
    // into it — the global jar may hold a different kid's cookies (only an ASSIGNED device may migrate).
    if (childId.length > 0) {
        self.blinkeredFocusChildId = childId;
        self.blinkeredCookieMigrateFromConfig = NO;
        // This picker login does its OWN comprehensive wipe + restore below, so the store now belongs to
        // this child — record it and mark the launch owner-check done so transferCookies (fired on the
        // post-login navigation) doesn't wipe again for the same kid.
        self.blinkeredCookieOwnerChecked = YES;
        [self blinkeredWriteCookieStoreOwner:childId];
    }
    // Operate on the shared config's data store — the same store transferCookies populates and the
    // window.open'd site popups read from.
    WKWebsiteDataStore *dataStore = self.wkWebViewConfiguration.websiteDataStore;
    if (!dataStore) dataStore = webView.configuration.websiteDataStore;
    WKHTTPCookieStore *cookieStore = dataStore.httpCookieStore;

    void (^navigate)(void) = ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            if (navUrl.length == 0) return;
            // navUrl is page-supplied (body[@"url"]). Correct escaping, but the SEMANTICS are the
            // problem here, not the syntax: this makes the APP navigate the main frame, so the
            // resulting navigation arrives at the interceptors carrying OUR origin on both
            // targetFrame and sourceFrame — origin laundering. The gate at the top of
            // didReceiveScriptMessage: is what closes that; this is only the escaping half.
            [webView evaluateJavaScript:[NSString stringWithFormat:@"location.replace(%@)",
                                         [SEBAbstractWebView blinkeredJSStringLiteral:navUrl]]
                      completionHandler:nil];
        });
    };

    if (!cookieStore) { navigate(); return; }

    if ([action isEqualToString:@"leave"]) {
        // Save the leaving child's cookies (the next login wipes + restores), then go to the picker.
        [cookieStore getAllCookies:^(NSArray<NSHTTPCookie *> *cookies) {
            [self blinkeredSaveCookies:cookies forChild:childId];
            navigate();
        }];
    } else if ([action isEqualToString:@"login"]) {
        // Wipe the current jar, restore THIS child's saved cookies, then load their session.
        // (transferCookies + exitSEB are now keyed to blinkeredFocusChildId so the global cookies.json
        // restore no longer re-injects the previous kid's logins into new windows.)
        {
            // Comprehensive wipe: deleting cookies alone does NOT kill a Clerk session — local &
            // session storage and IndexedDB rehydrate it — so clear every data type on the store,
            // then restore THIS child's saved cookies.
            NSSet *types = [WKWebsiteDataStore allWebsiteDataTypes];
            [dataStore removeDataOfTypes:types modifiedSince:[NSDate distantPast] completionHandler:^{
                // removeDataOfTypes is UNRELIABLE for cookies (it clears storage/cache but can leave
                // cookies behind), so authoritatively delete every cookie via the cookie-store API.
                [cookieStore getAllCookies:^(NSArray<NSHTTPCookie *> *remaining) {
                    dispatch_group_t delGroup = dispatch_group_create();
                    for (NSHTTPCookie *c in remaining) {
                        dispatch_group_enter(delGroup);
                        [cookieStore deleteCookie:c completionHandler:^{ dispatch_group_leave(delGroup); }];
                    }
                    dispatch_group_notify(delGroup, dispatch_get_main_queue(), ^{
                        {
                            NSArray<NSHTTPCookie *> *saved = [self blinkeredLoadCookiesForChild:childId];
                            if (saved.count == 0) { navigate(); return; }
                            dispatch_group_t setGroup = dispatch_group_create();
                            for (NSHTTPCookie *c in saved) {
                                dispatch_group_enter(setGroup);
                                [cookieStore setCookie:c completionHandler:^{ dispatch_group_leave(setGroup); }];
                            }
                            dispatch_group_notify(setGroup, dispatch_get_main_queue(), ^{ navigate(); });
                        }
                    });
                }];
            }];
        }
    } else {
        navigate();
    }
}

- (NSString *)blinkeredCookiePathForChild:(NSString *)childId
{
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir = [[appSupport stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"profile-cookies"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSCharacterSet *bad = [[NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"] invertedSet];
    NSString *safe = [[childId componentsSeparatedByCharactersInSet:bad] componentsJoinedByString:@"_"];
    if (safe.length == 0) safe = @"unknown";
    return [dir stringByAppendingPathComponent:[safe stringByAppendingPathExtension:@"plist"]];
}

// Legacy GLOBAL cookie jar: appSupport/Blinkered/cookies.json (JSON, written by exitSEB before per-child
// jars). Returns the cookies, or @[] if absent/empty. Used only for the one-time per-child migration.
- (NSArray<NSHTTPCookie *> *)blinkeredLoadGlobalCookies
{
    NSURL *appSupport = [[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *cookieFile = [[appSupport URLByAppendingPathComponent:@"Blinkered"] URLByAppendingPathComponent:@"cookies.json"];
    NSData *data = [NSData dataWithContentsOfURL:cookieFile];
    if (!data) return @[];
    NSArray *cookieArray = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![cookieArray isKindOfClass:[NSArray class]]) return @[];
    NSMutableArray<NSHTTPCookie *> *cookies = [NSMutableArray array];
    for (NSDictionary *d in cookieArray) {
        if (![d isKindOfClass:[NSDictionary class]]) continue;
        NSMutableDictionary *props = [NSMutableDictionary dictionary];
        props[NSHTTPCookieName]   = d[@"name"];
        props[NSHTTPCookieValue]  = d[@"value"];
        props[NSHTTPCookieDomain] = d[@"domain"];
        props[NSHTTPCookiePath]   = d[@"path"] ?: @"/";
        if (d[@"expires"]) props[NSHTTPCookieExpires] = [NSDate dateWithTimeIntervalSince1970:[d[@"expires"] doubleValue]];
        NSHTTPCookie *cookie = [NSHTTPCookie cookieWithProperties:props];
        if (cookie) [cookies addObject:cookie];
    }
    return cookies;
}

- (void)blinkeredDeleteGlobalCookieFile
{
    NSURL *appSupport = [[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] firstObject];
    NSURL *cookieFile = [[appSupport URLByAppendingPathComponent:@"Blinkered"] URLByAppendingPathComponent:@"cookies.json"];
    [[NSFileManager defaultManager] removeItemAtURL:cookieFile error:nil];
}

// Which child the shared persistent cookie store currently holds cookies for. A tiny text file next to the
// per-child jars; used to WIPE the store on a kid-change so a new kid never inherits the previous kid's cookies.
- (NSString *)blinkeredCookieStoreOwnerPath
{
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir = [appSupport stringByAppendingPathComponent:@"Blinkered"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return [dir stringByAppendingPathComponent:@"cookie-store-owner.txt"];
}
- (NSString *)blinkeredReadCookieStoreOwner
{
    NSString *s = [NSString stringWithContentsOfFile:[self blinkeredCookieStoreOwnerPath] encoding:NSUTF8StringEncoding error:nil];
    s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return s ?: @"";
}
- (void)blinkeredWriteCookieStoreOwner:(NSString *)childId
{
    [(childId ?: @"") writeToFile:[self blinkeredCookieStoreOwnerPath] atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

- (void)blinkeredSaveCookies:(NSArray<NSHTTPCookie *> *)cookies forChild:(NSString *)childId
{
    if (childId.length == 0) return;
    NSMutableArray *arr = [NSMutableArray array];
    for (NSHTTPCookie *c in cookies) { if (c.properties) [arr addObject:c.properties]; }
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:arr format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    if (data) {
        [data writeToFile:[self blinkeredCookiePathForChild:childId] atomically:YES];
        DDLogInfo(@"Blinkered: saved %lu cookies for child %@", (unsigned long)arr.count, childId);
    }
}

- (NSArray<NSHTTPCookie *> *)blinkeredLoadCookiesForChild:(NSString *)childId
{
    if (childId.length == 0) return @[];
    NSData *data = [NSData dataWithContentsOfFile:[self blinkeredCookiePathForChild:childId]];
    if (!data) return @[];
    NSArray *arr = [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:nil];
    if (![arr isKindOfClass:[NSArray class]]) return @[];
    NSMutableArray *cookies = [NSMutableArray array];
    for (NSDictionary *props in arr) {
        if (![props isKindOfClass:[NSDictionary class]]) continue;
        NSHTTPCookie *c = [NSHTTPCookie cookieWithProperties:props];
        if (c) [cookies addObject:c];
    }
    DDLogInfo(@"Blinkered: loaded %lu cookies for child %@", (unsigned long)cookies.count, childId);
    return cookies;
}


@end

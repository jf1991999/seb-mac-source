//
//  SEBAbstractWebView.m
//  Safe Exam Browser
//
//  Created by Daniel R. Schneider on 04.11.20.
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
//  Contributor(s): ______________________________________.
//

#import "SEBAbstractWebView.h"
#import "SEBAbstractClassicWebView.h"
#import "SafeExamBrowser-Swift.h"
#if TARGET_OS_OSX
#import "NSPasteboard+SaveRestore.h"
// For +blinkeredIsHomeLockSession, used by the ENFORCE state of the /seb-quit frame gate below
// (§8.6: enforce home locks first). macOS only — SEBBrowserWindow is an NSWindow subclass.
#import "SEBBrowserWindow.h"
#endif

@implementation SEBAbstractWebView

// See the header for the contract and for why this exists. Every
// -evaluateJavaScript: call site that interpolates a page-supplied value goes
// through here; none of them hand-roll escaping.
//
// The markers below are load-bearing: tools/lockdown-tests/run-js-escaping-test.sh
// slices this exact region out of this file and compiles it, so the test exercises
// the SHIPPED implementation rather than a copy that can drift. Do not remove or
// rename them — the test fails loudly if it cannot find them.
#pragma mark - Blinkered trusted origin (SEB_QUIT_HARDENING_PLAN §3.1)

// THE trusted-origin definition — "is this a document WE served?" — used by every control that
// decides whether page-originated input may weaken or end a lockdown. One definition, deliberately:
// two of these existed at one point and drifted.
//
// The deployment host is derived from the SIGNED CONFIG's quit URL rather than hardcoded. A
// hardcoded blinkered.com.au would break every non-prod deployment, because the shell page and the
// quit URL both come from the same cachedBaseUrl() — so on a staging base the legitimate unlock
// would fail its own gate. quitURL lives in SEB's private user defaults and has no page-reachable
// write path (the bridge's only mutating messages are setQuitPassword, which writes
// hashedQuitPassword alone, and updateURLFilter, which writes filter rules), so its host is
// authoritative and unforgeable by page content.
//
// NOTE the trusted set is captured per webview at construction, so a webview built before a
// reconfigure keeps the old quit host. Harmless on Mac — a re-lock relaunches the app — but stated
// here so it is not rediscovered as a bug.
+ (BOOL) blinkeredTrustedOriginHost:(NSString *)host protocol:(NSString *)protocol
{
    NSString *h = host.lowercaseString;

#ifdef DEBUG
    // Local dev server, debug builds only, never in a release binary. This clause is ORed over the
    // WHOLE predicate rather than nested inside the "not https" branch, deliberately: the previous
    // bridge gate had exactly these semantics, so https://localhost was trusted, and nesting it
    // would silently stop trusting anyone running a local HTTPS dev server.
    if ([h isEqualToString:@"localhost"] || [h isEqualToString:@"127.0.0.1"]) return YES;
#endif

    // https only. A control that ends or weakens a lockdown must not be reachable over a scheme an
    // on-path attacker can forge.
    if (![protocol isEqualToString:@"https"]) return NO;

    if ([h isEqualToString:@"blinkered.com.au"] || [h hasSuffix:@".blinkered.com.au"]) return YES;

    // Derive from the RAW pref: quitURLTrimmed has already been lowercased and had "/" stripped, so
    // a value configured without a scheme would yield host == nil and this clause would silently
    // contribute nothing.
    NSString *rawQuitURL = [[NSUserDefaults standardUserDefaults]
                            secureStringForKey:@"org_safeexambrowser_SEB_quitURL"];
    NSString *quitHost = [NSURL URLWithString:rawQuitURL].host.lowercaseString;
    return quitHost.length > 0 && [h isEqualToString:quitHost];
}

#pragma mark - Blinkered /seb-quit frame gate (SEB_QUIT_HARDENING_PLAN §3.2, §5 step 5)

// ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
// │ BLOCKING PRECONDITION — DO NOT RAISE THIS ABOVE 0 UNTIL THE §6 TAHOE DEVICE TEST HAS RUN.    │
// └──────────────────────────────────────────────────────────────────────────────────────────────┘
//
// On macOS 26/Tahoe the navigationAction.sourceFrame GETTER ITSELF crashes with
// "CFRetain() called with NULL" (EXC_BREAKPOINT) when there is no source frame — you cannot
// null-check the result, because you never get one — and that crash-LOOPS a locked device: every
// relaunch restores the same navigation and re-crashes. See the identical, already-shipped guard in
// the URL-filter block below, which was added after exactly that.
//
// The trap fires whenever the predicate is COMPUTED, so a "log-only" release is NOT a safe
// half-step: it computes the same predicate and would crash-loop identically. That is why this is a
// three-state switch rather than a log-only boolean — at 0 the predicate is never computed at all,
// so this code is inert and safe to ship while the device test is still outstanding.
//
//   0 = OFF        no predicate is computed. Today's behaviour exactly. <- DEFAULT
//   1 = LOG ONLY   compute, log and report a refusal, but still quit. Requires the §6 test.
//   2 = ENFORCE    refuse an untrusted quit. Requires 1 to have run a release with zero
//                  refusals on legitimate flows (§5 step 5), and enforces HOME LOCKS ONLY
//                  first (§8.6) — a wrong gate on a class session costs a teacher's exit code
//                  for a whole room, where a home lock has the agent force-quit behind it.
//
// The §6 test to run before raising this: on Tahoe, inside a real lock, confirm targetFrame is
// nil-safe on the SYNTHESIZED SEBWKNavigationAction (which overrides only navigationType and
// request, so both frame getters fall through to a WKNavigationAction with no WebKit backing
// store) and that the guard returns BEFORE the sourceFrame read. Drive it with
// window.open('<quit URL>') from an allowed page. Also: a server-redirect hop, and a
// session-restore navigation after relaunch.
#define BLINKERED_QUIT_FRAME_GATE 0

// The trust boundary for a quit-URL navigation. A quit ENDS THE LOCKDOWN, so it may only be
// triggered by a document WE served, navigating its own top level.
//
// EVALUATION ORDER IS NORMATIVE, not incidental. targetFrame is checked for nil FIRST and
// short-circuits, so the crash-prone sourceFrame getter is never reached without a target frame.
//
// Why BOTH frames. targetFrame is crash-safe where sourceFrame is not, but it does not suffice: with
// cross-frame targeting (frame A navigating a NAMED frame B) targetFrame is B — potentially our own
// shell — while the initiator is the attacker. sourceFrame alone carries the crash risk. Requiring
// both is strictly stronger than either and costs nothing here, because this predicate is only ever
// evaluated on an actual quit-URL navigation, and the app never navigates to its own quit URL
// programmatically (established by enumerating every loadURL: and openAndShowWebViewWithURL: call
// site in Classes/ — do NOT "confirm" this by grepping SEBController.m for quitURL, which would
// return nothing for the wrong reason: quitURL does not live there).
//
// What the main-frame check actually buys, stated honestly: because allowed sites open as full
// top-level windows, the main frame IS the primary attack surface and isMainFrame passes trivially
// for the ordinary case. It buys (a) closing the sandboxed-iframe variant, which is the cheapest
// attack and still constructible, and (b) being a precondition for reading a frame origin at all
// under the crash guard. THE ORIGIN CHECK IS THE WHOLE CONTROL.
//
// One consequence stated plainly: targetFrame == nil -> NO is a BEHAVIOUR CHANGE, not merely a crash
// guard — that is how the app sees every window.open. Verified safe today (all eight legitimate quit
// flows use window.location.href on an existing main frame), but it hard-codes an assumption that a
// future "open the quit URL in a window" pattern would break silently.
- (BOOL)blinkeredTrustedQuitNavigation:(WKNavigationAction *)navigationAction
{
    // CRASH GUARD — see the header comment. Never read sourceFrame without a target frame.
    // No legitimate quit flow uses a new window, so a nil target frame is untrusted.
    if (navigationAction.targetFrame == nil) return NO;
    if (!navigationAction.targetFrame.isMainFrame) return NO;

    // targetFrame is the document currently IN the frame being navigated — crash-safe, and for a
    // self-navigation it is exactly the initiator.
    WKSecurityOrigin *t = navigationAction.targetFrame.securityOrigin;
    if (![SEBAbstractWebView blinkeredTrustedOriginHost:t.host protocol:t.protocol]) return NO;

    // sourceFrame additionally closes cross-frame targeting.
    WKSecurityOrigin *s = navigationAction.sourceFrame.securityOrigin;
    return [SEBAbstractWebView blinkeredTrustedOriginHost:s.host protocol:s.protocol];
}

#pragma mark - Blinkered start-URL anchor (SEB_QUIT_HARDENING_PLAN §3.3)

// The URL -[SEBOSXBrowserController openMainBrowserWindow] actually navigates to.
//
// Compare against THIS, not the raw pref. openMainBrowserWindow appends `?<startURLQueryParameter>`
// when startURLAppendQueryParameter is set — and since the home start URL already carries a query,
// that appends a SECOND `?`, so the navigated URL could never equal the raw pref. The default is NO
// and nothing in this product sets it, so there is no divergence today — which is precisely the
// shape of every defect this design has already had: correctness resting on an unenumerated
// property of another subsystem. Worse, the appended value is not app-authored: it is harvested
// from a .seb download URL's second `?`, and a page inside a lock can trigger a .seb download.
// Reproducing the construction makes the comparison and the navigation the same function of the
// same inputs, so neither of those matters.
+ (NSURL *) blinkeredConfiguredStartURL
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    NSString *urlString = [preferences secureStringForKey:@"org_safeexambrowser_SEB_startURL"] ?: @"";
    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_startURLAppendQueryParameter"]) {
        NSString *queryString = [preferences secureStringForKey:@"org_safeexambrowser_startURLQueryParameter"];
        if (queryString.length > 0) {
            urlString = [NSString stringWithFormat:@"%@?%@", urlString, queryString];
        }
    }
    return urlString.length > 0 ? [NSURL URLWithString:urlString] : nil;
}

// Is this navigation THE configured start URL?
//
// This is the whole authorisation for the two start-URL interceptors. It replaces three earlier
// designs — a currentURL proxy, a one-shot latch, and an arm-on-loadURL: scheme — each of which
// anchored trust on an unenumerated property of some other subsystem (where line 1096 sits,
// interceptor-before-newTab ordering, nothing being able to steer a main-frame navigation) and each
// of which was broken by a later round. This one anchors on the SIGNED CONFIG: page content cannot
// author org_safeexambrowser_SEB_startURL. There is no state, no latch, no arming and no call-site
// dependency, so Retry, the reload branch, process-termination reload and session restart all just
// work — there is nothing to re-establish.
//
// Replay is the strongest attack and it fails: a kid can reconstruct the start URL exactly from the
// shell's own location.search, but the write is idempotent DURING THE LOCK (it rewrites
// home_session.json byte-identically and deletes an already-absent class_quit_hash.txt). Steering
// via a bridge message fails for the same reason — a steered navigation only writes if it IS the
// configured URL. NOTE the precision: idempotent during the lock, not during the UNLOCK window,
// where the agent has deleted home_session.json while the app is still running. A replay there
// re-creates the file unlock hygiene just removed. Fail-closed (a present home_session.json REFUSES
// setQuitPassword), so not an escape, but it is why the launch-time credential clear exists.
//
// THE COMPARISON IS THE DESIGN. Both naive forms are defective:
//   • Decoded (.path/.query) is many-to-one, so an attacker can redistribute percent-encoding — and
//     the extraction loops below read components.queryItems with NO break, so last occurrence wins.
//     Comparison and extraction would be two different functions of the same input.
//   • Raw (.percentEncodedQuery) makes correctness depend on WebKit's re-parse preserving the
//     config string's exact escaping — hex-digit case, which unreserved characters stay encoded —
//     through URL(string:) -> absoluteString -> URLWithString: -> URLRequest -> WTF::URL. The
//     failure mode is the write silently not happening.
// So: compare the PARSED QUERY ITEMS, which is what the extraction loops consume, as an ORDERED,
// field-wise list.
+ (BOOL) blinkeredIsConfiguredStartURL:(NSURL *)navigated
{
    return [self blinkeredURL:navigated matchesConfiguredStartURL:[self blinkeredConfiguredStartURL]];
}

// The comparison itself, as a pure function of two URLs. Split out from the pref read so
// tools/lockdown-tests/run-start-url-anchor-test.sh can slice this exact region out of this file
// and drive it — the comparison is where the outcome is decided, and the plan went through three
// designs before this one, so it is tested against the SHIPPED code rather than a copy of it.
// BEGIN blinkeredStartURLComparison
+ (BOOL) blinkeredURL:(NSURL *)navigated matchesConfiguredStartURL:(NSURL *)configured
{
    if (!navigated || !configured) return NO;

    NSURLComponents *n = [NSURLComponents componentsWithURL:navigated resolvingAgainstBaseURL:NO];
    NSURLComponents *c = [NSURLComponents componentsWithURL:configured resolvingAgainstBaseURL:NO];
    if (!n || !c) return NO;

    // A start URL never carries credentials or a fragment. Anything that does is not ours.
    if (n.user != nil || n.password != nil || n.fragment != nil) return NO;

    // Scheme and host case-insensitively (URL syntax), path exactly (it is case-sensitive).
    if (![n.scheme.lowercaseString isEqualToString:c.scheme.lowercaseString]) return NO;
    if (![n.host.lowercaseString isEqualToString:c.host.lowercaseString]) return NO;
    if (![(n.path ?: @"") isEqualToString:(c.path ?: @"")]) return NO;

    // Port EXPLICITLY. WebKit strips :443 where NSURL preserves it; treating the two as equal was
    // v2's defect 3, and its symptom is a silent no-write on a self-hosted deployment.
    NSNumber *nPort = n.port ?: [self blinkeredDefaultPortForScheme:n.scheme];
    NSNumber *cPort = c.port ?: [self blinkeredDefaultPortForScheme:c.scheme];
    if (nPort != cPort && ![nPort isEqualToNumber:cPort]) return NO;

    // Query items as an ORDERED list, not a multiset. The extraction loops are order-SENSITIVE
    // (no break, last wins), so an order-insensitive comparison would agree with them only while
    // every configured query name is unique. That is true today (home: id, token, base, sid, to;
    // class: code, token, base, to, h) but it is an unenumerated property of the server's URL
    // construction — this design's own thesis. Ordering costs nothing and removes the assumption.
    NSArray<NSURLQueryItem *> *nItems = n.queryItems;
    NSArray<NSURLQueryItem *> *cItems = c.queryItems;
    if ((nItems == nil) != (cItems == nil)) return NO;
    if (nItems.count != cItems.count) return NO;
    for (NSUInteger i = 0; i < cItems.count; i++) {
        NSURLQueryItem *ni = nItems[i], *ci = cItems[i];
        if (![ni.name isEqualToString:ci.name]) return NO;
        // nil and @"" are DISTINCT: `?sid` (no `=`) gives nil, `sid=` gives @"". The server emits
        // `sid=${encodeURIComponent(device.sessionId || '')}`, so the empty case is real, and a
        // comparison built by string concatenation would conflate or crash on it.
        if (ni.value == nil || ci.value == nil) {
            if (ni.value != ci.value) return NO;
        } else if (![ni.value isEqualToString:ci.value]) {
            return NO;
        }
    }
    return YES;
}

+ (NSNumber *) blinkeredDefaultPortForScheme:(NSString *)scheme
{
    NSString *s = scheme.lowercaseString;
    if ([s isEqualToString:@"https"]) return @443;
    if ([s isEqualToString:@"http"])  return @80;
    return nil;
}
// END blinkeredStartURLComparison

// BEGIN blinkeredJSStringLiteral
+ (NSString *) blinkeredJSStringLiteral:(NSString *)value
{
    // Non-strings fail closed to an empty string literal rather than being described
    // by -description, which would emit something that is not a JS string at all.
    return [self blinkeredJSLiteral:([value isKindOfClass:[NSString class]] ? value : @"")
                           fallback:@"\"\""];
}

// The general form, for call sites interpolating a whole JSON value (an array of
// window descriptors, say) rather than a single string.
+ (NSString *) blinkeredJSLiteral:(id)jsonObject fallback:(NSString *)fallback
{
    // NSJSONWritingFragmentsAllowed lets a bare string or number be the top-level
    // value (macOS 10.15+; our deployment target is 11.0).
    NSData *data = [NSJSONSerialization dataWithJSONObject:jsonObject
                                                   options:NSJSONWritingFragmentsAllowed
                                                     error:NULL];
    NSString *literal = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
    // Fail closed. A value NSJSONSerialization refuses (unpaired surrogates, a type
    // that is not JSON) becomes the caller's inert fallback, never an unescaped
    // interpolation.
    if (literal.length < 2) {
        return fallback;
    }
    // JSON leaves U+2028/U+2029 raw. ES2019 legalised them inside string literals,
    // so this is belt-and-braces rather than a live hole — but "safe because of
    // which ECMAScript edition the engine implements" is exactly the kind of
    // unenumerated dependency that produced this bug.
    literal = [literal stringByReplacingOccurrencesOfString:@"\u2028" withString:@"\\u2028"];
    literal = [literal stringByReplacingOccurrencesOfString:@"\u2029" withString:@"\\u2029"];
    return literal;
}
// END blinkeredJSStringLiteral

- (instancetype)initNewTabMainWebView:(BOOL)mainWebView
                       withCommonHost:(BOOL)commonHostTab
                        configuration:(WKWebViewConfiguration *)configuration
                   overrideSpellCheck:(BOOL)overrideSpellCheck
                             delegate:(nonnull id<SEBAbstractWebViewNavigationDelegate>)delegate
{
    self = [super init];
    _navigationDelegate = delegate;
    if (self) {
        _isMainBrowserWebView = mainWebView;
        _isReloadAllowed = [_navigationDelegate isReloadAllowedMainWebView:mainWebView];
        _showReloadWarning = [_navigationDelegate showReloadWarningMainWebView:mainWebView];
        _isNavigationAllowed = [_navigationDelegate isNavigationAllowedMainWebView:mainWebView];
        _overrideAllowSpellCheck = overrideSpellCheck;
        urlFilter = [SEBURLFilter sharedSEBURLFilter];
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        quitURLTrimmed = [[[preferences secureStringForKey:@"org_safeexambrowser_SEB_quitURL"] stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]] lowercaseString];
        webViewSelectPolicies webViewSelectPolicy = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_browserWindowWebView"];
        BOOL downloadingInTemporaryWebView = overrideSpellCheck;
        _allowSpellCheck = !_overrideAllowSpellCheck && [preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowSpellCheck"];
        _downloadPDFFiles = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_downloadPDFFiles"];

#if TARGET_OS_IPHONE
                // Override webViewSelectPolicy
                webViewSelectPolicy = webViewSelectForceModern;
#endif

        if (webViewSelectPolicy != webViewSelectForceClassic || downloadingInTemporaryWebView) {
            BOOL sendBrowserExamKey = [preferences secureBoolForKey:@"org_safeexambrowser_SEB_sendBrowserExamKey"];
            if ((webViewSelectPolicy == webViewSelectAutomatic && !sendBrowserExamKey) ||
                (webViewSelectPolicy == webViewSelectForceModern) ||
                (webViewSelectPolicy == webViewSelectForceModernInForeignNewTabs && (!sendBrowserExamKey || !commonHostTab)) ||
                downloadingInTemporaryWebView) {
                
                DDLogInfo(@"Opening modern WebView");
                SEBAbstractModernWebView *sebAbstractModernWebView = [[SEBAbstractModernWebView alloc] initWithDelegate:self configuration:configuration];
                self.browserControllerDelegate = sebAbstractModernWebView;
                [self initGeneralProperties];
                
                return self;
            }
        }
        DDLogInfo(@"Opening classic WebView");
        SEBAbstractClassicWebView *sebAbstractClassicWebView = [[SEBAbstractClassicWebView alloc] initWithDelegate:self];
        self.browserControllerDelegate = sebAbstractClassicWebView;
        [self initGeneralProperties];
    }
    
    return self;
}

- (void) initGeneralProperties
{
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    [self.browserControllerDelegate setPrivateClipboardEnabled:[preferences secureBoolForKey:@"org_safeexambrowser_SEB_enablePrivateClipboard"] ||
     [preferences secureBoolForKey:@"org_safeexambrowser_SEB_enablePrivateClipboardMacEnforce"]];
    [self.browserControllerDelegate setAllowDictionaryLookup:[preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowDictionaryLookup"]];
    [self.browserControllerDelegate setAllowPDFPlugIn:[preferences secureBoolForKey:@"org_safeexambrowser_SEB_allowPDFPlugIn"]];
}


#pragma mark - SEBAbstractBrowserControllerDelegate Methods

- (id)nativeWebView
{
    return self.browserControllerDelegate.nativeWebView;
}

- (void) closeWKWebView
{
    if ([self.browserControllerDelegate respondsToSelector:@selector(closeWKWebView)]) {
        [self.browserControllerDelegate closeWKWebView];
    }
}

- (NSURL*)url
{
    return [self.browserControllerDelegate url];
}

- (NSString*)pageTitle
{
    return [self.browserControllerDelegate pageTitle];
}

- (BOOL)canGoBack
{
    return [self.browserControllerDelegate canGoBack];
}

- (BOOL)canGoForward;
{
    return [self.browserControllerDelegate canGoForward];
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
    if (self.isReloadAllowed == NO) {
        return;
    }
    [self.browserControllerDelegate reload];
}

- (void)loadURL:(NSURL *)url
{
    if (url) {
        [self.browserControllerDelegate loadURL:url];
    }
}

- (void)stopLoading
{
    [self.browserControllerDelegate stopLoading];
}

- (void) focusFirstElement
{
    [self.browserControllerDelegate focusFirstElement];
}

- (void) focusLastElement
{
    [self.browserControllerDelegate focusLastElement];
}

- (BOOL) zoomPageSupported
{
    return self.browserControllerDelegate.zoomPageSupported;
}

- (void) zoomPageIn
{
    [self.browserControllerDelegate zoomPageIn];
}

- (void) zoomPageOut
{
    [self.browserControllerDelegate zoomPageOut];
}

- (void) zoomPageReset
{
    [self.browserControllerDelegate zoomPageReset];
}

- (void) textSizeIncrease
{
    [self.browserControllerDelegate textSizeIncrease];
}

- (void) textSizeDecrease
{
    [self.browserControllerDelegate textSizeDecrease];
}

- (void) textSizeReset
{
    [self.browserControllerDelegate textSizeReset];
}


- (void) searchText:(NSString *)textToSearch backwards:(BOOL)backwards caseSensitive:(BOOL)caseSensitive
{
    [self.browserControllerDelegate searchText:textToSearch backwards:backwards caseSensitive:caseSensitive];
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


- (void)loadView
{
    [self.browserControllerDelegate loadView];
}

- (void)didMoveToParentViewController
{
    [self.browserControllerDelegate didMoveToParentViewController];
}

- (void)viewDidLayout
{
    [self.browserControllerDelegate viewDidLayout];
}

- (void)viewDidLayoutSubviews
{
    [self.browserControllerDelegate viewDidLayoutSubviews];
}

- (void)viewWillTransitionToSize
{
    [self.browserControllerDelegate viewWillTransitionToSize];
}

- (void) viewDidLoad
{
    [self.browserControllerDelegate viewDidLoad];
}

- (void)viewWillAppear
{
    [self.browserControllerDelegate viewWillAppear];
}

- (void)viewWillAppear:(BOOL)animated
{
    [self.browserControllerDelegate viewWillAppear:(BOOL)animated];
}

- (void)viewDidAppear
{
    [self.browserControllerDelegate viewDidAppear];
}

- (void)viewDidAppear:(BOOL)animated
{
    [self.browserControllerDelegate viewDidAppear:(BOOL)animated];
}

- (void)viewWillDisappear
{
    [self.browserControllerDelegate viewWillDisappear];
}

- (void)viewWillDisappear:(BOOL)animated
{
    [self.browserControllerDelegate viewWillDisappear:(BOOL)animated];
}

- (void)viewWDidDisappear
{
    [self.browserControllerDelegate viewDidDisappear];
}

- (void)viewWDidDisappear:(BOOL)animated
{
    [self.browserControllerDelegate viewDidDisappear:(BOOL)animated];
}


- (void) stopMediaPlaybackWithCompletionHandler:(void (^)(void))completionHandler
{
    if ([self.browserControllerDelegate respondsToSelector:@selector(stopMediaPlaybackWithCompletionHandler:)]) {
        [self.browserControllerDelegate stopMediaPlaybackWithCompletionHandler:completionHandler];
    } else {
        completionHandler();
    }
}


- (void)toggleScrollLock
{
    if ([self.browserControllerDelegate respondsToSelector:@selector(toggleScrollLock)]) {
        [self.browserControllerDelegate toggleScrollLock];
    }
}

- (BOOL)isScrollLockActive
{
    if ([self.browserControllerDelegate respondsToSelector:@selector(isScrollLockActive)]) {
        return [self.browserControllerDelegate isScrollLockActive];
    }
    return NO;
}


- (void)disableFlashFullscreen
{
#if TARGET_OS_OSX
    [self.browserControllerDelegate disableFlashFullscreen];
#endif
}


- (void)setDownloadingSEBConfig:(BOOL)downloadingSEBConfig
{
    if ([self.browserControllerDelegate respondsToSelector:@selector(downloadingSEBConfig)]) {
        self.browserControllerDelegate.downloadingSEBConfig = downloadingSEBConfig;
    }
}


#pragma mark - SEBAbstractWebViewNavigationDelegate Methods

- (WKWebViewConfiguration *) wkWebViewConfiguration
{
    return self.navigationDelegate.wkWebViewConfiguration;
}

- (id<WKScriptMessageHandler>) blinkeredScriptMessageHandler
{
    // Optional protocol method — guard so a delegate that doesn't implement it
    // can't crash with an unrecognized selector during webview setup.
    if ([self.navigationDelegate respondsToSelector:@selector(blinkeredScriptMessageHandler)]) {
        return self.navigationDelegate.blinkeredScriptMessageHandler;
    }
    return nil;
}

- (id) accessibilityDock
{
    return self.navigationDelegate.accessibilityDock;
}

- (void) setLoading:(BOOL)loading
{
    [self.navigationDelegate setLoading:loading];
}

- (void) setCanGoBack:(BOOL)canGoBack canGoForward:(BOOL)canGoForward
{
    [self.navigationDelegate setCanGoBack:canGoBack canGoForward:canGoForward];
}

- (void) examineCookies:(NSArray<NSHTTPCookie *>*)cookies forURL:(NSURL *)url
{
    [self.navigationDelegate examineCookies:cookies forURL:url];
}

- (void) examineHeaders:(NSDictionary<NSString *,NSString *>*)headerFields forURL:(NSURL *)url
{
    [self.navigationDelegate examineHeaders:headerFields forURL:url];
}

- (void) firstDOMElementDeselected
{
    if ([self.navigationDelegate respondsToSelector:@selector(firstDOMElementDeselected)]) {
        [self.navigationDelegate firstDOMElementDeselected];
   }
}

- (void) lastDOMElementDeselected
{
    if ([self.navigationDelegate respondsToSelector:@selector(lastDOMElementDeselected)]) {
        [self.navigationDelegate lastDOMElementDeselected];
    }
}

- (SEBAbstractWebView *) openNewTabWithURL:(NSURL *)url
                             configuration:(WKWebViewConfiguration *)configuration
{
    return [self.navigationDelegate openNewTabWithURL:url configuration:configuration];
}

- (SEBAbstractWebView *) openNewWebViewWindowWithURL:(NSURL *)url
                                       configuration:(WKWebViewConfiguration *)configuration
{
    return [self.navigationDelegate openNewWebViewWindowWithURL:url configuration:configuration];
}

- (void) makeActiveAndOrderFront
{
    [self.navigationDelegate makeActiveAndOrderFront];
}

- (void) showWebView:(SEBAbstractWebView *)webView
{
    [self.navigationDelegate showWebView:webView];
}

- (void) closeWebView
{
    [self.navigationDelegate closeWebView:self];
}

- (void) closeWebView:(SEBAbstractWebView *)webView
{
    [self.navigationDelegate closeWebView:webView];
}

- (void) addWebView:(id)nativeWebView
{
    if ([self.navigationDelegate respondsToSelector:@selector(addWebView:)]) {
        [self.navigationDelegate addWebView:nativeWebView];
    }
}

- (void) addWebViewController:(id)webViewController
{
    if ([self.navigationDelegate respondsToSelector:@selector(addWebViewController:)]) {
        [self.navigationDelegate addWebViewController:webViewController];
    }
}

- (SEBAbstractWebView *) abstractWebView
{
    return self;
}

- (NSURL *)currentURL
{
    return self.navigationDelegate.currentURL;
}

- (NSString *)currentMainHost
{
    return self.navigationDelegate.currentMainHost;
}

- (void)setCurrentMainHost:(NSString *)currentMainHost
{
    self.navigationDelegate.currentMainHost = currentMainHost;
}

- (BOOL)isMainBrowserWebViewActive
{
    return self.isMainBrowserWebView;
}

- (NSString *)quitURL
{
    return self.navigationDelegate.quitURL;
}

- (NSString *)pageJavaScript
{
    return self.navigationDelegate.pageJavaScript;
}

- (BOOL)allowDownloads
{
    return self.navigationDelegate.allowDownloads;
}

- (BOOL)allowUploads
{
    return self.navigationDelegate.allowUploads;
}

- (void)showAlertNotAllowedDownUploading:(BOOL)uploading
{
    [self.navigationDelegate showAlertNotAllowedDownUploading:uploading];
}

- (void)showAlertNotAllowedDownloadingAndOpeningSebConfig:(BOOL)downloading
{
    [self.navigationDelegate showAlertNotAllowedDownloadingAndOpeningSebConfig:downloading];
}

- (BOOL)overrideAllowSpellCheck
{
    return _overrideAllowSpellCheck;
}

- (BOOL)isUsingServerBEK
{
    return self.navigationDelegate.isUsingServerBEK;
}

- (NSURLRequest *)modifyRequest:(NSURLRequest *)request
{
    return [self.navigationDelegate modifyRequest:request];
}

- (NSString *) browserExamKeyForURL:(NSURL *)url
{
    return [self.navigationDelegate browserExamKeyForURL:url];
}

- (NSString *) configKeyForURL:(NSURL *)url
{
    return [self.navigationDelegate configKeyForURL:url];
}

- (NSString *) appVersion
{
    return [self.navigationDelegate appVersion];
}


- (void) searchTextMatchFound:(BOOL)matchFound
{
    [self.navigationDelegate searchTextMatchFound:matchFound];
}


@synthesize customSEBUserAgent;

- (NSString *) customSEBUserAgent
{
    return self.navigationDelegate.customSEBUserAgent;
    
}


- (NSArray <NSData *> *) privatePasteboardItems
{
    return self.navigationDelegate.privatePasteboardItems;
}

- (void) setPrivatePasteboardItems:(NSArray<NSData *> *)privatePasteboardItems
{
    self.navigationDelegate.privatePasteboardItems = privatePasteboardItems;
}

- (void) storePasteboard {
#if TARGET_OS_OSX
    NSPasteboard *generalPasteboard = [NSPasteboard generalPasteboard];
    NSArray *archive = [generalPasteboard archiveObjects];
    self.navigationDelegate.privatePasteboardItems = archive;
    [generalPasteboard clearContents];
#endif
}

- (void) restorePasteboard {
#if TARGET_OS_OSX
    NSPasteboard *generalPasteboard = [NSPasteboard generalPasteboard];
    [generalPasteboard clearContents];
    NSArray *archive = self.navigationDelegate.privatePasteboardItems;
    [generalPasteboard restoreArchive:archive];
#endif
}


- (void) presentAlertWithTitle:(NSString *)title
                       message:(NSString *)message
{
    [self.navigationDelegate presentAlertWithTitle:title message:message];
}


- (SEBBackgroundTintStyle) backgroundTintStyle
{
    return [self.navigationDelegate backgroundTintStyle];
}


- (id) window
{
    return self.navigationDelegate.window;
}

- (BOOL) isAACEnabled
{
    return self.navigationDelegate.isAACEnabled;
}

- (void)sebWebViewDidStartLoad
{
//    NSHTTPCookieStorage *cookieJar = [NSHTTPCookieStorage sharedHTTPCookieStorage];
//    NSArray<NSHTTPCookie *> *cookies = cookieJar.cookies;
//    [self.navigationDelegate examineCookies:cookies];

    [self.navigationDelegate sebWebViewDidStartLoad];
    if (self.isNavigationAllowed == NO && [self.browserControllerDelegate respondsToSelector:@selector(clearBackForwardList)]) {
        [self.browserControllerDelegate clearBackForwardList];
    }
}


- (void)webView:(WKWebView *)webView
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    if (self.navigationDelegate == nil) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    } else {
        [self.navigationDelegate webView:webView didReceiveAuthenticationChallenge:challenge completionHandler:completionHandler];
    }
}


- (void)sebWebViewDidFinishLoad
{
    [self.navigationDelegate sebWebViewDidFinishLoad];

    NSURL *pageURL = self.url;
    NSString *pageTitle = self.pageTitle;
    if (pageTitle.length == 0) {
        if (pageURL.pathExtension && [pageURL.pathExtension caseInsensitiveCompare:filenameExtensionPDF] == NSOrderedSame) {
            pageTitle = pageURL.lastPathComponent;
        } else {
            pageTitle = @"";
        }
    }
    [self.navigationDelegate setPageTitle:pageTitle];

    [self.navigationDelegate setCanGoBack:self.canGoBack canGoForward:self.canGoForward];
}


// [R1-5] A main-frame load failure of OUR OWN content during a home session, with a
// connectivity-class error, means the lock is stranded on a network that can't reach Blinkered
// (offline / DNS / timeout / TLS-trust failure — the 3 Aug incident). Returns YES when the offline
// panel was triggered (the caller then skips the generic load-error alert — the panel replaces it).
// Ordinary in-lock site failures (a blocked third-party page) fall through to current behaviour.
// NOTE: the cert-reject case often surfaces as −999 (cancelled), which this method never sees —
// that trigger lives in the cert-challenge cancel path (SEBBrowserController). The exact error the
// WKWebView emits after a cancelled challenge must be confirmed on the mitmproxy rig (plan §5.1)
// before this code set is considered final.
- (BOOL)blinkeredOfflinePanelForLoadError:(NSError *)error
{
    if (!self.isMainBrowserWebView) return NO;
    static NSSet *connectivityCodes;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        connectivityCodes = [NSSet setWithArray:@[
            @(NSURLErrorTimedOut),                       // −1001
            @(NSURLErrorCannotFindHost),                 // −1003
            @(NSURLErrorCannotConnectToHost),            // −1004
            @(NSURLErrorNetworkConnectionLost),          // −1005
            @(NSURLErrorDNSLookupFailed),                // −1006
            @(NSURLErrorNotConnectedToInternet),         // −1009
            @(NSURLErrorSecureConnectionFailed),         // −1200
            @(NSURLErrorServerCertificateHasBadDate),    // −1201
            @(NSURLErrorServerCertificateUntrusted),     // −1202
            @(NSURLErrorServerCertificateHasUnknownRoot),// −1203
            @(NSURLErrorServerCertificateNotYetValid),   // −1204
        ]];
    });
    if (![error.domain isEqualToString:NSURLErrorDomain] || ![connectivityCodes containsObject:@(error.code)]) return NO;
    // Only during a home session (identity file written at lock start) — scope to OUR lock first.
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *sessionPath = [[appSupport stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"home_session.json"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:sessionPath]) return NO;
    // Resolve the failing page's host from whichever key WebKit populated: the URL-OBJECT key
    // (NSURLErrorFailingURLErrorKey — what the offline −1009 error actually carries), the string
    // key, or the webview's current URL. On the rig (Maggie's Mac, 3 Aug) a −1009 failure carried
    // ONLY the URL-object key and currentURL was nil during the failed provisional load, so reading
    // just the STRING key left host empty and silently skipped the panel. Since we've already scoped
    // to the MAIN webview of an active HOME session (our content shell — third-party sites open in
    // separate windows, never here), only bail when we POSITIVELY identify a non-Blinkered host.
    // An unknown/empty host still shows the panel: a stranded parent needs the way out.
    NSURL *failingURL = [error.userInfo objectForKey:NSURLErrorFailingURLErrorKey];
    if (![failingURL isKindOfClass:[NSURL class]]) failingURL = nil;
    NSString *failingURLString = [error.userInfo objectForKey:NSURLErrorFailingURLStringErrorKey];
    NSString *host = failingURL.host ?: ([NSURL URLWithString:failingURLString ?: @""].host ?: self.currentURL.host);
    if (host.length && !([host isEqualToString:@"blinkered.com.au"] || [host hasSuffix:@".blinkered.com.au"])) return NO;
    BOOL certKind = (error.code <= NSURLErrorSecureConnectionFailed && error.code >= NSURLErrorServerCertificateNotYetValid);
    DDLogError(@"Blinkered: home-session content load failed with connectivity error %ld (%@) — showing offline panel", (long)error.code, certKind ? @"TLS-trust class" : @"offline class");
    [[NSNotificationCenter defaultCenter] postNotificationName:@"blinkeredHomeConnectivityFailed"
                                                        object:self
                                                      userInfo:@{ @"kind": certKind ? @"cert" : @"offline",
                                                                  @"host": host,
                                                                  @"code": @(error.code) }];
    return YES;
}

- (void)sebWebViewDidFailLoadWithError:(NSError *)error
{
    if (error.code == -999) {
        DDLogError(@"%s: Load Error -999: Another request initiated before the previous request was completed (%@)", __FUNCTION__, error.description);
        return;
    }
    // [R1-5] Stranded home lock → native offline panel instead of the generic load-error alert.
    if ([self blinkeredOfflinePanelForLoadError:error]) {
        [self.navigationDelegate setLoading:NO];
        return;
    }
    [self.navigationDelegate setLoading:NO];
    // Enable back/forward buttons according to availablility for this webview
    [self.navigationDelegate setCanGoBack:self.canGoBack canGoForward:self.canGoForward];

    // Don't display the error 102 "Frame load interrupted", this can be caused by
    // the URL filter canceling loading a blocked URL
    if (error.code == 102) {
        DDLogDebug(@"%s: Reported Error 102: %@", __FUNCTION__, error.description);
        
    // Don't display the error 204 "Plug-in handled load"
    } else if (error.code == 204) {
        DDLogDebug(@"%s: Reported Error 204: %@", __FUNCTION__, error.description);

    } else {
        
        DDLogError(@"%s: Load Error: %@", __FUNCTION__, error.description);
        
        // Decide if of failed load should be displayed in the alert
        // (according to current ShowURL policy settings for exam/additional tab)
        BOOL showURL = false;
        NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
        if (self.isMainBrowserWebView) {
            if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_browserWindowShowURL"] >= browserWindowShowURLOnlyLoadError) {
                showURL = true;
            }
        } else {
            if ([preferences secureIntegerForKey:@"org_safeexambrowser_SEB_newBrowserWindowShowURL"] >= browserWindowShowURLOnlyLoadError) {
                showURL = true;
            }
        }
        NSMutableDictionary<NSErrorUserInfoKey,id> *userInfo = error.userInfo.mutableCopy;
        NSString *failingURLString = [error.userInfo objectForKey:NSURLErrorFailingURLStringErrorKey];
        NSString *errorMessage = [NSString stringWithFormat:@"%@%@", error.localizedDescription, showURL ? [NSString stringWithFormat:@"\n%@", failingURLString] : @""];
        [userInfo setValue:errorMessage forKey:NSLocalizedDescriptionKey];
        NSError *updatedError = [[NSError alloc] initWithDomain:error.domain code:error.code userInfo:userInfo.copy];
        error = updatedError;
    }
    
    [self.navigationDelegate sebWebViewDidFailLoadWithError:error];
}


// Blinkered: best-effort report of a blocked MAIN-frame navigation to the server, so the parent (and we,
// while tuning the allow-list) get notified that a page didn't load. Deduped per host for the process
// lifetime so it never spams; identity comes from home_session.json (written at lock time). Mirrors the
// existing security-event POST pattern.
// [§3.5] A refused control URL is reportable, and the credentials MUST come from agent.json rather
// than home_session.json.
//
// That is not a style choice. The whole point of this signal is the degraded state §3.3 permits — a
// session whose start-URL write was refused or skipped — and in that state home_session.json is
// exactly what is missing. -blinkeredReportBlockedNavigation: below reads home_session.json and
// would therefore go silent precisely when this signal is needed. agent.json exists independently of
// any session file, so a device in the degraded state can still report it.
//
// Two purposes: parent alerting on a real escape attempt, and field evidence that no LEGITIMATE flow
// is being refused — which is what §5's staged rollout leans on before enforcement is turned up.
//
// Throttled per (path, reason) for the same reason the bridge report is: these interceptors fire on
// navigations a page can drive in a loop, and an uncoalesced POST path on a locked child's device is
// a battery and network drain with no symptom the watchdog can see.
+ (void)blinkeredReportControlURLRefused:(NSURL *)url reason:(NSString *)reason
{
    NSString *key = [NSString stringWithFormat:@"%@|%@", url.path ?: @"?", reason ?: @"?"];
    static NSMutableDictionary<NSString *, NSDate *> *lastReported;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ lastReported = [NSMutableDictionary dictionary]; });
    @synchronized (lastReported) {
        NSDate *last = lastReported[key];
        if (last && [[NSDate date] timeIntervalSinceDate:last] < 300.0) return;
        if (!last && lastReported.count >= 32) [lastReported removeAllObjects];
        lastReported[key] = [NSDate date];
    }

    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *agentJson = [[appSupport stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"agent.json"];
    NSData *credData = [NSData dataWithContentsOfFile:agentJson];
    NSDictionary *creds = credData ? [NSJSONSerialization JSONObjectWithData:credData options:0 error:nil] : nil;
    if (![creds isKindOfClass:[NSDictionary class]]) return;
    NSString *devId = creds[@"id"], *devTok = creds[@"token"];
    NSString *server = [creds[@"server"] isKindOfClass:[NSString class]] ? creds[@"server"] : @"https://blinkered.com.au";
    if (![devId isKindOfClass:[NSString class]] || ![devTok isKindOfClass:[NSString class]]) return;
    NSURL *endpoint = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/home/devices/%@/security-event", server, devId]];
    if (!endpoint) return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:endpoint];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{ @"token": devTok,
                                                              @"type": @"control_url_refused" }
                                                   options:0 error:nil];
    if (req.HTTPBody) {
        [[[NSURLSession sharedSession] dataTaskWithRequest:req] resume];
        DDLogInfo(@"Blinkered: reported control_url_refused (%@, %@)", url.path ?: @"?", reason);
    }
}

- (void)blinkeredReportBlockedNavigation:(NSURL *)blockedURL linkActivated:(BOOL)linkActivated source:(NSString *)source
{
    NSString *host = blockedURL.host;
    if (host.length == 0) return;
    static NSMutableSet *reportedHosts;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ reportedHosts = [NSMutableSet new]; });
    @synchronized (reportedHosts) {
        if ([reportedHosts containsObject:host]) return;
        [reportedHosts addObject:host];
    }
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [[appSupport stringByAppendingPathComponent:@"Blinkered"] stringByAppendingPathComponent:@"home_session.json"];
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return;
    NSDictionary *info = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![info isKindOfClass:[NSDictionary class]]) return;
    NSString *base = info[@"base"], *deviceId = info[@"id"], *token = info[@"token"];
    if (base.length == 0 || deviceId.length == 0 || token.length == 0) return;
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/home/devices/%@/blocked-nav", base, deviceId]];
    if (!url) return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    // linkActivated: the child actively clicked a link to leave (an escape — server keeps it blocked).
    // source: the allowed site they were on (so the server can auto-classify auth/redirect flows).
    NSDictionary *payload = @{ @"token": token,
                              @"url": blockedURL.absoluteString ?: @"",
                              @"linkActivated": @(linkActivated),
                              @"source": source ?: @"" };
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    if (req.HTTPBody) {
        [[[NSURLSession sharedSession] dataTaskWithRequest:req] resume];
        DDLogInfo(@"Blinkered: reported blocked page to server (%@, click=%d)", host, linkActivated);
    }
}


- (SEBNavigationAction *)decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction
                                                      newTab:(BOOL)newTab
                                           configuration:(WKWebViewConfiguration *)configuration
                                        downloadFilename:(nullable NSString *)downloadFilename
{
    NSURLRequest *request = navigationAction.request;
    NSURL *url = request.URL;
    DDLogVerbose(@"[SEBAbstractWebView decidePolicyForNavigationAction: newTab: %hhd configuration:%@ downloadFilename:%@]: request = %@, URL = %@", newTab, configuration, downloadFilename, request, url);
    WKNavigationType navigationType = navigationAction.navigationType;
    NSString *httpMethod = request.HTTPMethod;
    //    NSDictionary<NSString *,NSString *> *allHTTPHeaderFields = request.allHTTPHeaderFields;
    DDLogVerbose(@"Navigation type for URL %@: %ld", url, (long)navigationType);
    DDLogVerbose(@"HTTP method for URL %@: %@", url, httpMethod);
    //    DDLogVerbose(@"All HTTP header fields for URL %@: %@", url, allHTTPHeaderFields);
    
    NSUserDefaults *preferences = [NSUserDefaults standardUserDefaults];
    
    NSURL *originalURL = url;
    SEBNavigationAction *newNavigationAction = [SEBNavigationAction new];
    newNavigationAction.policy = SEBNavigationActionPolicyCancel;
    
    // This is currently used for SEB Server handshake after logging in to Moodle
    if (navigationType == WKNavigationTypeFormSubmitted) {
        [self.navigationDelegate shouldStartLoadFormSubmittedURL:url];
    }
    
    // Check if quit URL has been clicked (regardless of current URL Filter)
    if ([[[originalURL.absoluteString stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]] lowercaseString] isEqualToString:quitURLTrimmed]) {
        // [§3.2] THE HOLE THIS PLAN EXISTS FOR. navigationAction carries targetFrame and sourceFrame
        // and neither was ever consulted: no origin check, no frame check, no referrer check. This
        // fires for main frames AND sub-frames, and the comment above is literal — it runs 150 lines
        // BEFORE the URL filter, so filter containment cannot help even in principle. Any page a kid
        // can get content onto inside a lock (a published Google Doc, an LMS post, their own
        // allow-listed domain, a sandboxed iframe navigating itself) ends a home lockdown with
        // `location = '<quit URL>'`. Silent: no password, no prompt, no server involvement. And no
        // server-side change can mitigate it — the Mac app never reads quitURLConfirm — so the
        // exposure window is the update window.
#if BLINKERED_QUIT_FRAME_GATE > 0
        if (![self blinkeredTrustedQuitNavigation:navigationAction]) {
            DDLogError(@"Blinkered SECURITY: /seb-quit from an UNTRUSTED navigation — "
                       @"targetFrame=%@ isMain=%d",
                       navigationAction.targetFrame ? @"present" : @"nil",
                       navigationAction.targetFrame.isMainFrame);
            [SEBAbstractWebView blinkeredReportControlURLRefused:originalURL reason:@"untrusted-quit-navigation"];
#if BLINKERED_QUIT_FRAME_GATE > 1 && TARGET_OS_OSX
            // ENFORCE — home locks only for the first enforcing release (§8.6). A wrong gate on a
            // class session costs a teacher's exit code for a whole room; a home lock has the
            // agent's force-quit behind it. Refuse by falling through to the URL filter rather than
            // cancelling, so a flow we failed to anticipate degrades rather than dies.
            if ([SEBBrowserWindow blinkeredIsHomeLockSession]) {
                DDLogError(@"Blinkered SECURITY: refusing the quit (home lock, enforcing)");
                return newNavigationAction;
            }
#endif
        }
#endif
        [[NSNotificationCenter defaultCenter]
         postNotificationName:@"quitLinkDetected" object:self];
        return newNavigationAction;
    }

    // REMOVED: the /seb-setquit interceptor (SEB_QUIT_HARDENING_PLAN §1.6, §3.3, §5 step 2b).
    //
    // It read ?h= and wrote it to class_quit_hash.txt, and deleted home_session.json
    // UNCONDITIONALLY — before the hash was even parsed. Worse, like its siblings below it
    // matched on originalURL.path with NO HOST CHECK AT ALL, so any frame in any window could
    // fire it from any host: https://evil.example/seb-setquit performed the write.
    //
    // What accepting a hostile hash bought a kid (§1.6):
    //   1. The native quit dialog validating THEIR password. SEBController prefers
    //      class_quit_hash.txt over the config's hashedQuitPassword, and home configs set
    //      allowQuit with the parent's Master Exit Code hash, so the dialog branch is entered.
    //   2. The brute-force throttle DISARMED. isHomeQuit = !hasClassSession && homeSessionInfo
    //      != nil — writing a class hash makes the first false and deleting the file makes the
    //      second nil, so both halves fail at once and the 5-wrong/60s-doubling/15-min-cap
    //      ladder never engages. The Master Exit Code becomes brute-forceable at full speed.
    //   3. The offline re-lock marker lost (the parent-exit marker needs home_session.json).
    //   4. The setQuitPassword home refusal disarmed — it keys on that file existing.
    //
    // Not one-step, since blinkeredShowHomeExitModal gates on the webview URL containing
    // /home/ rather than on the file, so Cmd+Q still reaches the in-page modal first. But its
    // 0.7 s fallback deadline drops to the native dialog, which the kid now owns the password
    // to. A full escape with one extra step.
    //
    // Deleted rather than gated: it has ZERO legitimate callers. Over seb-classroom it existed
    // only as a route definition (now also deleted) and one doc line; its former caller
    // (join.html) was removed long ago and the per-class hash ships via /seb-setsession?...&h=.
    // No shipped page has ever called it, so there is no old-page-with-new-app risk. Removing a
    // primitive beats guarding one.
    //
    // The [R2-2] stale-home_session.json cleanup this used to perform is NOT lost — it moves to
    // the launch-time credential clear (§3.4/§5 step 3), which covers home lock, home Focus,
    // class and static in one place and does not sit in an attacker-reachable interceptor.

    // Intercept /seb-setsession?code=...&token=...&base=...&h=...&to=<url>
    // Writes class_session.json (for native-quit server notification) and class_quit_hash.txt,
    // then allows navigation so the server redirects to the content page.
    if ([originalURL.path isEqualToString:@"/seb-setsession"]) {
        // [§3.3] Authorised ONLY when this navigation IS the signed config's start URL. Note this
        // also closes the host-freedom hole: the path test above has no host check at all, so
        // https://evil.example/seb-setsession used to perform the write.
        if (![SEBAbstractWebView blinkeredIsConfiguredStartURL:originalURL]) {
            // NEVER CANCEL — skip the write and ALLOW. A cancelled navigation cost an earlier
            // version of this design a blank locked window with no shell, which is a worse outcome
            // than a degraded one: the agent's watchdog relaunches only when the app is NOT running,
            // so a blank-but-running app is neither repaired nor reported. An attacker gains nothing
            // by being allowed through — there is no write, and safeRedirect constrains ?to= to the
            // server's allow-list — while a legitimate flow we failed to anticipate degrades rather
            // than dies.
            DDLogError(@"Blinkered SECURITY: /seb-setsession refused — not the configured start URL. "
                       @"No class session or quit hash written; navigation allowed.");
            [SEBAbstractWebView blinkeredReportControlURLRefused:originalURL reason:@"not-start-url"];
            newNavigationAction.policy = SEBNavigationActionPolicyAllow;
            return newNavigationAction;
        }
        NSURLComponents *components = [NSURLComponents componentsWithURL:originalURL resolvingAgainstBaseURL:NO];
        NSString *code = nil, *token = nil, *base = nil, *hash = nil;
        for (NSURLQueryItem *item in components.queryItems) {
            if ([item.name isEqualToString:@"code"])  code  = item.value;
            if ([item.name isEqualToString:@"token"]) token = item.value;
            if ([item.name isEqualToString:@"base"])  base  = item.value;
            if ([item.name isEqualToString:@"h"])     hash  = item.value;
        }
        NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
        NSString *dir = [appSupport stringByAppendingPathComponent:@"Blinkered"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        // [R2-2] Entering a CLASS session — clear any stale home_session.json. It is removed only
        // on a clean native home-quit, so a remote unlock / crash / watchdog kill of a prior home
        // lock leaves it behind; the home-only gates (offline panel, setQuitPassword refusal) key
        // on this file existing, so a leftover would fire home behaviour inside a class session.
        [[NSFileManager defaultManager] removeItemAtPath:[dir stringByAppendingPathComponent:@"home_session.json"] error:nil];
        // Write class_session.json so SEBController can call /api/class/:code/native-quit
        if (code.length > 0 && token.length > 0 && base.length > 0) {
            NSDictionary *sessionInfo = @{@"code": code, @"token": token, @"base": base};
            NSData *data = [NSJSONSerialization dataWithJSONObject:sessionInfo options:0 error:nil];
            if (data) {
                [data writeToFile:[dir stringByAppendingPathComponent:@"class_session.json"] atomically:YES];
                DDLogInfo(@"Blinkered: class session info written (code=%@)", code);
            }
        }
        // Write or clear class_quit_hash.txt for the native password dialog.
        NSString *hashFilePath = [dir stringByAppendingPathComponent:@"class_quit_hash.txt"];
        if ([hash isKindOfClass:[NSString class]] && hash.length == 64) {
            [hash writeToFile:hashFilePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            DDLogInfo(@"Blinkered: quit hash written via seb-setsession");
        } else {
            // No password required for this session — remove any stale hash from a previous session
            // so the native quit dialog is not shown erroneously.
            [[NSFileManager defaultManager] removeItemAtPath:hashFilePath error:nil];
            DDLogInfo(@"Blinkered: quit hash cleared (no password required for this session)");
        }
        newNavigationAction.policy = SEBNavigationActionPolicyAllow;
        return newNavigationAction;
    }

    // Intercept /seb-sethomesession?id=...&token=...&base=...&to=<content-url>
    // Writes home_session.json (for native-quit server notification) and clears any
    // stale class_quit_hash.txt so a prior class password cannot unlock a home session.
    if ([originalURL.path isEqualToString:@"/seb-sethomesession"]) {
        // [§3.3] Authorised ONLY when this navigation IS the signed config's start URL. Without it,
        // a hostile frame could re-point the home session's identity at a server IT controls — which
        // is where native-quit, blocked-nav reports and security events go — and, because the path
        // test has no host check, could do it from any host at all.
        if (![SEBAbstractWebView blinkeredIsConfiguredStartURL:originalURL]) {
            // NEVER CANCEL — see the identical note on /seb-setsession above.
            DDLogError(@"Blinkered SECURITY: /seb-sethomesession refused — not the configured start URL. "
                       @"No home session written; navigation allowed.");
            [SEBAbstractWebView blinkeredReportControlURLRefused:originalURL reason:@"not-start-url"];
            newNavigationAction.policy = SEBNavigationActionPolicyAllow;
            return newNavigationAction;
        }
        NSURLComponents *components = [NSURLComponents componentsWithURL:originalURL resolvingAgainstBaseURL:NO];
        NSString *deviceId = nil, *token = nil, *base = nil, *sessionId = nil, *toURL = nil;
        for (NSURLQueryItem *item in components.queryItems) {
            if ([item.name isEqualToString:@"id"])    deviceId  = item.value;
            if ([item.name isEqualToString:@"token"]) token     = item.value;
            if ([item.name isEqualToString:@"base"])  base      = item.value;
            if ([item.name isEqualToString:@"sid"])   sessionId = item.value;
            if ([item.name isEqualToString:@"to"])    toURL     = item.value;
        }
        // [R1-3] The lock's session UUID must land in home_session.json — the offline parent-exit
        // marker matches the agent's persisted lock on it. Newer servers send &sid= directly;
        // fall back to extracting it from the content URL's own &sid= (it has always been there).
        if (sessionId.length == 0 && toURL.length > 0) {
            NSURLComponents *toComponents = [NSURLComponents componentsWithString:toURL];
            for (NSURLQueryItem *item in toComponents.queryItems) {
                if ([item.name isEqualToString:@"sid"]) { sessionId = item.value; break; }
            }
        }
        NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
        NSString *dir = [appSupport stringByAppendingPathComponent:@"Blinkered"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        if (deviceId.length > 0 && token.length > 0 && base.length > 0) {
            NSMutableDictionary *sessionInfo = [@{@"id": deviceId, @"token": token, @"base": base} mutableCopy];
            if (sessionId.length > 0) sessionInfo[@"sessionId"] = sessionId;
            NSData *data = [NSJSONSerialization dataWithJSONObject:sessionInfo options:0 error:nil];
            if (data) {
                [data writeToFile:[dir stringByAppendingPathComponent:@"home_session.json"] atomically:YES];
                DDLogInfo(@"Blinkered: home session info written (device=%@, sessionId=%@)", deviceId, sessionId.length ? sessionId : @"<none>");
            }
        }
        // Remove stale class_quit_hash.txt — home sessions must not inherit a prior class password.
        [[NSFileManager defaultManager] removeItemAtPath:[dir stringByAppendingPathComponent:@"class_quit_hash.txt"] error:nil];
        DDLogInfo(@"Blinkered: class quit hash cleared for home session");
        newNavigationAction.policy = SEBNavigationActionPolicyAllow;
        return newNavigationAction;
    }

    if (urlFilter.enableURLFilter && ![self.navigationDelegate downloadingInTemporaryWebView]) {
        URLFilterRuleActions filterActionResponse = [urlFilter testURLAllowed:originalURL];
        if (filterActionResponse != URLFilterActionAllow) {
            // Blinkered: report only MAIN-frame page blocks to the server — a page the kid actually
            // tried to open that didn't load — NOT blocked ad/tracker iframes (targetFrame present and
            // not the main frame), which would be noise. targetFrame==nil = a new-window/top-level nav.
            BOOL isMainFrameNav = (navigationAction.targetFrame == nil || navigationAction.targetFrame.isMainFrame);
            if (isMainFrameNav) {
                // linkActivated = the child actively clicked a link to leave (escape → stays blocked);
                // source = the allowed page they were on (lets the server auto-classify auth/redirects).
                BOOL linkActivated = (navigationType == WKNavigationTypeLinkActivated);
                // CRASH GUARD (macOS 26 / new WebKit): for a NEW-WINDOW navigation — window.open(),
                // which is exactly how the research lane opens its browser — targetFrame is nil and
                // navigationAction.sourceFrame's getter can crash with "CFRetain() called with NULL"
                // (EXC_BREAKPOINT), because the source frame is null. That crash-LOOPS a locked device
                // (every relaunch restores the same nav and re-crashes). Only read sourceFrame when
                // there is a target frame (an in-page / main-frame nav, where it is populated); for a
                // new-window nav fall back to the current page URL. macOS 15 never nulled it, so it only
                // surfaced once a test Mac was on Tahoe.
                NSString *source;
                if (navigationAction.targetFrame != nil) {
                    source = navigationAction.sourceFrame.request.URL.absoluteString ?: @"";
                } else {
                    source = self.currentURL.absoluteString ?: @"";
                }
                [self blinkeredReportBlockedNavigation:originalURL linkActivated:linkActivated source:source];
            }
            /// Content is not allowed: Show teach URL alert if activated or just indicate URL is blocked filterActionResponse == URLFilterActionBlock ||
            // We show the URL blocked overlay message only if a link was actively tapped by the user
            if ((navigationType == WKNavigationTypeLinkActivated || urlFilter.learningMode)) {
                if ([self.navigationDelegate showURLFilterAlertForRequest:request forContentFilter:NO filterResponse:filterActionResponse] == NO) {
                    /// User didn't allow the content, don't load it
                    DDLogWarn(@"A clicked link was blocked by the URL filter");
                    DDLogDebug(@"This clicked link was blocked by the URL filter: %@", originalURL.absoluteString);
                    return newNavigationAction;
                }
            } else {
                DDLogDebug(@"This resource was blocked by the URL filter: %@", originalURL.absoluteString);
                return newNavigationAction;
            }
        }
    }
    
    NSString *fileExtension = [url pathExtension];
    
    if (newTab) {
        newBrowserWindowPolicies newBrowserWindowPolicy = [preferences secureIntegerForKey:@"org_safeexambrowser_SEB_newBrowserWindowByLinkPolicy"];
        
        // First check if links requesting to be opened in a new windows are generally blocked
        if (newBrowserWindowPolicy != getGenerallyBlocked) {
            // load link only if it's on the same host like the one of the current page
            if (![preferences secureBoolForKey:@"org_safeexambrowser_SEB_newBrowserWindowByLinkBlockForeign"] ||
                [self.navigationDelegate.currentMainHost isEqualToString:request.URL.host]) {
                if (newBrowserWindowPolicy == openInNewWindow) {
                    // Open in new tab
                    DDLogInfo(@"Open new window/tab URL in new window");
                    newNavigationAction.openedWebView = [self.navigationDelegate openNewTabWithURL:url configuration:(WKWebViewConfiguration *)configuration];
                    if (configuration) {
                        // Special case of window opened with Javascript .open() in a modern WebView (WKWebView)
                        newNavigationAction.policy = SEBNavigationActionPolicyJSOpen;
                        return newNavigationAction;
                    }
                    return newNavigationAction;
                }
                if (newBrowserWindowPolicy == openInSameWindow) {
                    // Load URL request in existing tab
                    DDLogInfo(@"Open new window/tab URL in same window (selected in current settings)");
                    if (configuration) {
                        // Special case of window opened with Javascript .open() in a modern WebView (WKWebView)
                        newNavigationAction.policy = SEBNavigationActionPolicyJSOpen;
                    }
                    [self loadURL:url];
                    //                    newNavigationAction.openedWebView = self;
                    return newNavigationAction;
                }
            }
        }
        // Opening links in new windows is not allowed by current policies
        // We show the URL blocked overlay message only if a link was actively tapped by the user
        if (navigationType == WKNavigationTypeLinkActivated) {
            [self.navigationDelegate showURLFilterAlertForRequest:request forContentFilter:NO filterResponse:SEBURLFilterAlertBlock];
        }
        DDLogInfo(@"Opening new window/tab URL generally blocked in current settings");
        return newNavigationAction;
    }
    BOOL WKDownloadSupported = NO;
    if (@available(macOS 11.3, iOS 14.5, *)) {
        WKDownloadSupported = YES;
    }
    if (![[self.browserControllerDelegate class] isEqual:SEBAbstractModernWebView.class]) {
        WKDownloadSupported = NO;
    }
    if (!WKDownloadSupported) {
        if ([url.scheme isEqualToString:@"data"]) {
            NSString *urlResourceSpecifier = [[url resourceSpecifier] stringByRemovingPercentEncoding];
            DDLogDebug(@"resourceSpecifier of data: URL is %@", urlResourceSpecifier);
            NSRange mediaTypeRange = [urlResourceSpecifier rangeOfString:@","];
            if (mediaTypeRange.location != NSNotFound && mediaTypeRange.location > 0 && urlResourceSpecifier.length > mediaTypeRange.location) {
                NSString *mediaType = [[urlResourceSpecifier substringToIndex:mediaTypeRange.location] lowercaseString];
                NSArray *mediaTypeParameters = [mediaType componentsSeparatedByString:@";"];
                if ([mediaTypeParameters indexOfObject:SEBConfigMIMEType] != NSNotFound) {
                    if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_downloadAndOpenSebConfig"] == NO) {
                        [self.navigationDelegate showAlertNotAllowedDownloadingAndOpeningSebConfig:YES];
                    } else {
                        NSString *sebConfigString = [urlResourceSpecifier substringFromIndex:mediaTypeRange.location+1];
                        NSData *sebConfigData;
                        if ([mediaTypeParameters indexOfObject:@"base64"] == NSNotFound) {
                            sebConfigData = [sebConfigString dataUsingEncoding:NSUTF8StringEncoding];
                        } else {
                            sebConfigData = [[NSData alloc] initWithBase64EncodedString:sebConfigString options:NSDataBase64DecodingIgnoreUnknownCharacters];
                        }
                        [self.navigationDelegate openSEBConfigFromData:sebConfigData];
                    }
                } else if (self.allowDownloads) {
                    NSString *fileDataString = [urlResourceSpecifier substringFromIndex:mediaTypeRange.location+1];
                    NSData *fileData;
                    if ([mediaTypeParameters indexOfObject:@"base64"] == NSNotFound) {
                        fileData = [fileDataString dataUsingEncoding:NSUTF8StringEncoding];
                    } else {
                        fileData = [[NSData alloc] initWithBase64EncodedString:fileDataString options:NSDataBase64DecodingIgnoreUnknownCharacters];
                    }
                    NSString *filename = [self saveData:fileData downloadFilename:downloadFilename];
                    if (filename) {
                        DDLogInfo(@"Successfully saved website generated data: %@", url);
                        [self.navigationDelegate fileDownloadedSuccessfully:filename];
                    } else {
                        DDLogError(@"Failed to save website generated data: %@", url);
                        [self.navigationDelegate presentAlertWithTitle:NSLocalizedString(@"Download Failed", @"") message:[NSString stringWithFormat:NSLocalizedString(@"Could not save downloaded data, probably a wrong download directory was used in %@ settings.", @""), SEBShortAppName]];
                    }
                } else if (!self.allowDownloads && navigationType == WKNavigationTypeLinkActivated) {
                    [self.navigationDelegate showAlertNotAllowedDownUploading:NO];
                }
            }
            newNavigationAction.policy = SEBNavigationActionPolicyCancel;
            return newNavigationAction;
        }
    }
    // Check if this is a seb:// or sebs:// link or a .seb file link
    if (((url.scheme && [url.scheme caseInsensitiveCompare:SEBProtocolScheme] == NSOrderedSame) ||
        (url.scheme && [url.scheme caseInsensitiveCompare:SEBSSecureProtocolScheme] == NSOrderedSame) ||
        (fileExtension && [fileExtension caseInsensitiveCompare:SEBFileExtension] == NSOrderedSame))) {
        if ([preferences secureBoolForKey:@"org_safeexambrowser_SEB_downloadAndOpenSebConfig"]) {
            // If the scheme is seb(s):// or the file extension .seb,
            // we (conditionally) download and open the linked .seb file
            if (!self.navigationDelegate.downloadingInTemporaryWebView) {
                [self.navigationDelegate conditionallyDownloadAndOpenSEBConfigFromURL:url];
                return newNavigationAction;
            }
        } else {
            [self.navigationDelegate showAlertNotAllowedDownloadingAndOpeningSebConfig:YES];
            return newNavigationAction;
        }
    }

    self.navigationDelegate.currentURL = url;
    self.navigationDelegate.currentMainHost = url.host;
    newNavigationAction.policy = SEBNavigationResponsePolicyAllow;
    return newNavigationAction;
}


- (NSString *)saveData:(NSData *)data downloadFilename:(nullable NSString *)downloadFilename
{
    // Get the path to the App's Documents directory
    NSString *filename;
    if (downloadFilename.length > 0) {
        filename = downloadFilename;
    } else {
        filename = NSLocalizedString(@"Untitled", @"untitled filename");
        NSDate *time = [NSDate date];
        NSDateFormatter* dateFormatter = [NSDateFormatter new];
        dateFormatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US"];
        [dateFormatter setDateFormat:@"yyyy-MM-dd_hh-mm-ss"];
        NSString *timeString = [dateFormatter stringFromDate:time];
        filename = [NSString stringWithFormat:@"%@_%@", filename, timeString];
    }
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    int fileIndex = 1;
    NSURL *directory = self.downloadPathURL;
    NSString* filenameWithoutExtension = [filename stringByDeletingPathExtension];
    NSString* fileExtension = [filename pathExtension];

    while ([fileManager fileExistsAtPath:[directory URLByAppendingPathComponent:filename isDirectory:NO].path]) {
        filename = [NSString stringWithFormat:@"%@-%d.%@", filenameWithoutExtension, fileIndex, fileExtension];
        fileIndex++;
    }
    BOOL success = [fileManager createFileAtPath:[directory URLByAppendingPathComponent:filename isDirectory:NO].path contents:data attributes:nil];
    if (success) {
        filename = [directory URLByAppendingPathComponent:filename isDirectory:NO].path;
        DDLogInfo(@"%s at file path: %@", __FUNCTION__, filename);
        return filename;
    } else {
        return nil;
    }
}


- (void)sebWebViewDidUpdateTitle:(nullable NSString *)title
{
    if ([self.navigationDelegate respondsToSelector:@selector(sebWebViewDidUpdateTitle:)]) {
        [self.navigationDelegate sebWebViewDidUpdateTitle:title];
    }
}


- (void)sebWebViewDidUpdateProgress:(double)progress
{
    if ([self.navigationDelegate respondsToSelector:@selector(sebWebViewDidUpdateProgress:)]) {
        [self.navigationDelegate sebWebViewDidUpdateProgress:progress];
    }
}


- (SEBNavigationResponsePolicy)decidePolicyForMIMEType:(NSString*)mimeType
                                                   url:(NSURL *)url
                                       canShowMIMEType:(BOOL)canShowMIMEType
                                        isForMainFrame:(BOOL)isForMainFrame
                                     suggestedFilename:(NSString *)suggestedFilename
                                               cookies:(NSArray <NSHTTPCookie *>*)cookies
{
    DDLogVerbose(@"decidePolicyForMIMEType: %@, URL: %@, canShowMIMEType: %d, isForMainFrame: %d, suggestedFilename %@", mimeType, url.absoluteString, canShowMIMEType, isForMainFrame, suggestedFilename);
    
    [self.navigationDelegate examineCookies:cookies forURL:url];
    
    if ((mimeType && [mimeType caseInsensitiveCompare:SEBConfigMIMEType] == NSOrderedSame) ||
        (mimeType && [mimeType caseInsensitiveCompare:SEBUnencryptedConfigMIMEType] == NSOrderedSame) ||
        (url.pathExtension && [url.pathExtension caseInsensitiveCompare:SEBFileExtension] == NSOrderedSame)) {
        // If MIME-Type or extension of the file indicates a .seb file, we (conditionally) download and open it
        NSURL *originalURL = self.originalURL;
        self.downloadingSEBConfig = YES;
        [self.navigationDelegate downloadSEBConfigFileFromURL:url originalURL:originalURL cookies:cookies];
        return SEBNavigationActionPolicyCancel;
    }

    // Check for PDF file and according to settings either download or display it inline in the SEB browser
    if (!((mimeType && [mimeType caseInsensitiveCompare:mimeTypePDF] == NSOrderedSame) && self.navigationDelegate.allowDownloads && _downloadPDFFiles)) {
        // MIME type isn't PDF or downloading of PDFs isn't allowed
        if (canShowMIMEType) {
            return SEBNavigationActionPolicyAllow;
        }
    }
    // If MIME type cannot be displayed by the WebView, then we download it
    DDLogInfo(@"MIME type to download is %@", mimeType);
    return SEBNavigationActionPolicyDownload;
}


- (void)webViewDidClose:(WKWebView *)webView
{
    [self.navigationDelegate closeWebView:self];
}


- (void)webView:(WKWebView *)webView
runJavaScriptAlertPanelWithMessage:(NSString *)message
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(void))completionHandler
{
    [self.navigationDelegate webView:webView runJavaScriptAlertPanelWithMessage:message initiatedByFrame:frame completionHandler:completionHandler];
}

- (void)pageTitle:(NSString *)pageTitle
runJavaScriptAlertPanelWithMessage:(NSString *)message
{
    [self.navigationDelegate pageTitle:pageTitle runJavaScriptAlertPanelWithMessage:message];
}

- (void)webView:(WKWebView *)webView
runJavaScriptConfirmPanelWithMessage:(NSString *)message
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(BOOL result))completionHandler
{
    [self.navigationDelegate webView:webView runJavaScriptConfirmPanelWithMessage:message initiatedByFrame:frame completionHandler:completionHandler];
}

- (BOOL)pageTitle:(NSString *)pageTitle
runJavaScriptConfirmPanelWithMessage:(NSString *)message
{
    return [self.navigationDelegate pageTitle:pageTitle runJavaScriptConfirmPanelWithMessage:message];
}

- (void)webView:(WKWebView *)webView
runJavaScriptTextInputPanelWithPrompt:(NSString *)prompt
    defaultText:(nullable NSString *)defaultText
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(NSString *result))completionHandler
{
    [self.navigationDelegate webView:webView runJavaScriptTextInputPanelWithPrompt:prompt defaultText:defaultText initiatedByFrame:frame completionHandler:completionHandler];
}

- (NSString *)pageTitle:(NSString *)pageTitle
runJavaScriptTextInputPanelWithPrompt:(NSString *)prompt
          defaultText:(NSString *)defaultText
{
    return [self.navigationDelegate pageTitle:pageTitle runJavaScriptTextInputPanelWithPrompt:prompt defaultText:defaultText];
}

- (void)webView:(WKWebView *)webView
runOpenPanelWithParameters:(id)parameters
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(NSArray<NSURL *> *URLs))completionHandler
{
    [self.navigationDelegate webView:webView runOpenPanelWithParameters:parameters initiatedByFrame:frame completionHandler:completionHandler];
}


- (BOOL) showURLFilterAlertForRequest:(NSURLRequest *)request
                     forContentFilter:(BOOL)contentFilter
                       filterResponse:(URLFilterRuleActions)filterResponse
{
    return [self.navigationDelegate showURLFilterAlertForRequest:request forContentFilter:contentFilter filterResponse:filterResponse];
}


- (NSURL *) downloadPathURL
{
    return self.navigationDelegate.downloadPathURL;
}

- (void) downloadFileFromURL:(NSURL *)url filename:(NSString *)filename cookies:(NSArray <NSHTTPCookie *>*)cookies
{
    [self.navigationDelegate downloadFileFromURL:url filename:filename cookies:cookies];
}

- (void) fileDownloadedSuccessfully:(NSString *)path
{
    [self.navigationDelegate fileDownloadedSuccessfully:path];
}


- (BOOL) downloadingInTemporaryWebView
{
    return [self.navigationDelegate downloadingInTemporaryWebView];
}

@end


@implementation SEBWKNavigationAction

- (void)setNavigationType:(WKNavigationType)navigationType
{
    _writableNavigationType = navigationType;
}

- (WKNavigationType)navigationType
{
    if (_writableNavigationType) {
        return _writableNavigationType;
    } else {
        return super.navigationType;
    }
}

- (void)setRequest:(NSURLRequest *)request
{
    _writableRequest = request;
}

- (NSURLRequest *)request
{
    if (_writableRequest) {
        return _writableRequest;
    } else {
        return super.request;
    }
}

@end


@implementation SEBNavigationAction

@end

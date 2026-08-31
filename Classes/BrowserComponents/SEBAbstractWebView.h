//
//  SEBAbstractWebView.h
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

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import "SEBURLFilter.h"

NS_ASSUME_NONNULL_BEGIN

@class SEBAbstractWebView;
@class SEBURLFilter;
@class WKWebView;
@class SEBNavigationAction;

@protocol SEBAbstractBrowserControllerDelegate <NSObject>

@optional
- (id) nativeWebView;
- (void) closeWKWebView;
- (nullable NSURL*) url;
- (nullable NSString*) pageTitle;
- (BOOL) canGoBack;
- (BOOL) canGoForward;

- (void) goBack;
- (void) goForward;
- (void) clearBackForwardList;
- (void) loadURL:(NSURL *)url;
- (void) stopLoading;
- (void) reload;

- (void) focusFirstElement;
- (void) focusLastElement;

@property (readonly) BOOL zoomPageSupported;
- (void) zoomPageIn;
- (void) zoomPageOut;
- (void) zoomPageReset;
- (void) updateZoomScale:(double)zoomScale;

- (void) textSizeIncrease;
- (void) textSizeDecrease;
- (void) textSizeReset;

- (NSString *) stringByEvaluatingJavaScriptFromString:(NSString *)js;

- (void) searchText:(nullable NSString *)textToSearch backwards:(BOOL)backwards caseSensitive:(BOOL)caseSensitive;

- (void) privateCopy:(id)sender;
- (void) privateCut:(id)sender;
- (void) privatePaste:(id)sender;
- (void) clearPrivatePasteboard;

- (void) loadView;
- (void) didMoveToParentViewController;
- (void) viewDidLayout;
- (void) viewDidLayoutSubviews;
- (void) viewWillTransitionToSize;
- (void) viewDidLoad;
- (void) viewWillAppear;
- (void) viewWillAppear:(BOOL)animated;
- (void) viewDidAppear;
- (void) viewDidAppear:(BOOL)animated;
- (void) viewWillDisappear;
- (void) viewWillDisappear:(BOOL)animated;
- (void) viewDidDisappear;
- (void) viewDidDisappear:(BOOL)animated;

- (void) stopMediaPlaybackWithCompletionHandler:(void (^)(void))completionHandler;

- (void) toggleScrollLock;
- (BOOL) isScrollLockActive;

- (void) setPrivateClipboardEnabled:(BOOL)privateClipboardEnabled;
- (void) setAllowDictionaryLookup:(BOOL)allowDictionaryLookup;
- (void) setAllowPDFPlugIn:(BOOL)allowPDFPlugIn;

- (void) disableFlashFullscreen;

- (void) sessionTaskDidCompleteSuccessfully:(NSURLSessionTask *)task;

@property (readwrite, nonatomic) BOOL downloadingSEBConfig;

@end


@protocol SEBAbstractWebViewNavigationDelegate <NSObject>

@optional
@property (readonly, nonatomic) WKWebViewConfiguration *wkWebViewConfiguration;
// The handler for the "blinkered" script message (getOpenWindows / focusWindow).
// Exposed so the modern WebView can re-register it on its own user content
// controller — it builds a fresh one and would otherwise drop the handler.
@property (nullable, readonly, nonatomic) id<WKScriptMessageHandler> blinkeredScriptMessageHandler;
@property (nullable, readonly, nonatomic) id accessibilityDock;
- (void) setPageTitle:(NSString *)title;
- (void) setLoading:(BOOL)loading;
- (void) setCanGoBack:(BOOL)canGoBack canGoForward:(BOOL)canGoForward;
- (void) examineCookies:(NSArray<NSHTTPCookie *>*)cookies forURL:(NSURL *)url;
- (void) examineHeaders:(NSDictionary<NSString *,NSString *>*)headerFields forURL:(NSURL *)url;
- (void) firstDOMElementDeselected;
- (void) lastDOMElementDeselected;

- (SEBAbstractWebView *) openNewTabWithURL:(nullable NSURL *)url
                             configuration:(nullable WKWebViewConfiguration *)configuration;
- (SEBAbstractWebView *) openNewWebViewWindowWithURL:(nullable NSURL *)url
                                       configuration:(nullable WKWebViewConfiguration *)configuration;

- (void) makeActiveAndOrderFront;
- (void) showWebView:(SEBAbstractWebView *)webView;
- (void) closeWebView;
- (void) closeWebView:(SEBAbstractWebView *)webView;
- (void) addWebView:(id)nativeWebView;
- (void) addWebViewController:(id)webViewController;

@property (readonly, nonatomic) SEBAbstractWebView *abstractWebView;
@property (nullable, strong, nonatomic) NSURL *currentURL;
@property (strong, nonatomic) NSString  *_Nullable currentMainHost;
@property (readonly) BOOL isMainBrowserWebViewActive;
@property (readwrite) BOOL isMainBrowserWebView;
@property (readwrite) BOOL isNavigationAllowed;
- (BOOL) isNavigationAllowedMainWebView:(BOOL)mainWebView;
@property (readwrite) BOOL isReloadAllowed;
- (BOOL) isReloadAllowedMainWebView:(BOOL)mainWebView;
@property (readwrite) BOOL showReloadWarning;
- (BOOL) showReloadWarningMainWebView:(BOOL)mainWebView;
- (NSString *) webPageTitle:(NSString *)title orURL:(NSURL *)url mainWebView:(BOOL)mainWebView;
@property (readonly, nonatomic) NSString *quitURL;
@property (readonly, nonatomic) NSString *pageJavaScript;
@property (readonly) BOOL allowDownloads;
@property (readonly) BOOL allowUploads;
- (void) showAlertNotAllowedDownUploading:(BOOL)uploading;
- (void) showAlertNotAllowedDownloadingAndOpeningSebConfig:(BOOL)downloading;
@property (readonly) BOOL downloadPDFFiles;
@property (readonly) BOOL directConfigDownloadAttempted;
@property (readonly) BOOL allowSpellCheck;
@property (readonly) BOOL overrideAllowSpellCheck;
@property (readonly) BOOL isUsingServerBEK;
- (NSURLRequest *) modifyRequest:(NSURLRequest *)request;
- (NSString *) browserExamKeyForURL:(NSURL *)url;
- (NSString *) configKeyForURL:(NSURL *)url;
- (NSString *) appVersion;

@property (readwrite, nonatomic) double pageZoom;

- (void) searchTextMatchFound:(BOOL)matchFound;


@property (readonly, nonatomic) NSString *customSEBUserAgent;
// Currently required by SEB-macOS
@property (nullable, readwrite, nonatomic) NSArray<NSData *> *privatePasteboardItems;
- (void) storePasteboard;
- (void) restorePasteboard;

- (void) presentAlertWithTitle:(NSString *)title
                       message:(NSString *)message;

// Required by SEB-iOS
- (SEBBackgroundTintStyle) backgroundTintStyle;

// Required by SEB-macOS
@property (weak, nonatomic) id __nullable window;
@property (readonly) BOOL isAACEnabled;

// Required by SEB-iOS
@property (strong, nonatomic) id __nullable uiAlertController;

- (void)sebWebViewDidStartLoad;
// The main frame has COMMITTED a document — i.e. there is now something in the webview. Distinct
// from DidFinishLoad, which can be arbitrarily later (or never) on a page with a hung subresource.
// SEBBrowserWindow uses it to take down the empty-content backdrop the moment real content lands
// (OFFLINE_RETRY_DEAD_END_PLAN §5 C7′) — a curtain over a working lock page is its own outage.
- (void)sebWebViewDidCommitLoad;
- (void)sebWebViewDidFinishLoad;
- (void)sebWebViewDidFailLoadWithError:(NSError *)error;
- (SEBNavigationAction *)decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction
                                                  newTab:(BOOL)newTab
                                           configuration:(nullable WKWebViewConfiguration *)configuration
                                        downloadFilename:(nullable NSString *)downloadFilename;
- (void)sebWebViewDidUpdateTitle:(nullable NSString *)title;
- (void)sebWebViewDidUpdateProgress:(double)progress;
- (SEBNavigationResponsePolicy)decidePolicyForMIMEType:(nullable NSString*)mimeType
                                                   url:(nullable NSURL *)url
                                       canShowMIMEType:(BOOL)canShowMIMEType
                                        isForMainFrame:(BOOL)isForMainFrame
                                     suggestedFilename:(nullable NSString *)suggestedFilename
                                               cookies:(nullable NSArray <NSHTTPCookie *>*)cookies;

- (void)webView:(WKWebView *)webView
didStartProvisionalNavigation:(null_unspecified WKNavigation *)navigation;

- (void)webView:(WKWebView *)webView
didReceiveServerRedirectForProvisionalNavigation:(null_unspecified WKNavigation *)navigation;

- (void)webView:(WKWebView *)webView
didFailProvisionalNavigation:(null_unspecified WKNavigation *)navigation withError:(NSError *)error;

- (void)webView:(nullable WKWebView *)webView
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *__nullable credential))completionHandler;

- (void)webView:(WKWebView *)webView
didCommitNavigation:(WKNavigation *)navigation;

- (void)webView:(WKWebView *)webView
didFinishNavigation:(WKNavigation *)navigation;

- (void)webViewWebContentProcessDidTerminate:(WKWebView *)webView;

- (void)webView:(WKWebView *)webView
decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction
decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler;

- (void)webView:(WKWebView *)webView
decidePolicyForNavigationResponse:(WKNavigationResponse *)navigationResponse
decisionHandler:(void (^)(WKNavigationResponsePolicy))decisionHandler;

- (nullable WKWebView *)webView:(WKWebView *)webView
createWebViewWithConfiguration:(WKWebViewConfiguration *)configuration
   forNavigationAction:(WKNavigationAction *)navigationAction
        windowFeatures:(WKWindowFeatures *)windowFeatures;

- (void)webViewDidClose:(WKWebView *)webView;

- (void)webView:(WKWebView *)webView
runJavaScriptAlertPanelWithMessage:(NSString *)message
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(void))completionHandler;

- (void)pageTitle:(NSString *)pageTitle
runJavaScriptAlertPanelWithMessage:(NSString *)message;

- (void)webView:(WKWebView *)webView
runJavaScriptConfirmPanelWithMessage:(NSString *)message
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(BOOL result))completionHandler;

- (BOOL)pageTitle:(NSString *)pageTitle
runJavaScriptConfirmPanelWithMessage:(NSString *)message;

- (void)webView:(WKWebView *)webView
runJavaScriptTextInputPanelWithPrompt:(NSString *)prompt
    defaultText:(nullable NSString *)defaultText
initiatedByFrame:(WKFrameInfo *)frame
completionHandler:(void (^)(NSString *result))completionHandler;

- (NSString *)pageTitle:(NSString *)pageTitle
runJavaScriptTextInputPanelWithPrompt:(NSString *)prompt
            defaultText:(NSString *)defaultText;

- (void)webView:(nullable WKWebView *)webView
runOpenPanelWithParameters:(id)parameters
initiatedByFrame:(nullable WKFrameInfo *)frame
completionHandler:(void (^)(NSArray<NSURL *> *URLs))completionHandler;

- (void)webView:(WKWebView *)webView
navigationAction:(WKNavigationAction *)navigationAction
didBecomeDownload:(WKDownload *)download API_AVAILABLE(macos(11.3), ios(14.5));

- (WKPermissionDecision)permissionDecisionForType:(WKMediaCaptureType)type API_AVAILABLE(macos(12.0), ios(15.0));
@property (readonly) BOOL browserMediaCaptureScreen;
- (void) shouldStartLoadFormSubmittedURL:(NSURL *)url;
- (void) transferCookiesToWKWebViewWithCompletionHandler:(void (^)(void))completionHandler;
#if TARGET_OS_IPHONE
- (void) presentViewController:(UIViewController *)viewControllerToPresent animated: (BOOL)flag completion:(void (^ __nullable)(void))completion;
#endif
- (BOOL) showURLFilterAlertForRequest:(NSURLRequest *)request
                     forContentFilter:(BOOL)contentFilter
                       filterResponse:(URLFilterRuleActions)filterResponse;
- (void) loadWebPageOrSearchResultWithString:(NSString *)webSearchString;

// Currently required by SEB-iOS
- (void) openCloseSliderForNewTab;
- (void) switchToTab:(nullable id)sender;
- (void) switchToNextTab;
- (void) switchToPreviousTab;
- (void) closeTab;
- (void) closeTabWithIndex:(NSUInteger)tabIndex;

@property (readonly) NSURL *downloadPathURL;
- (void) downloadFileFromURL:(NSURL *)url filename:(NSString *)filename cookies:(NSArray <NSHTTPCookie *>*)cookies;
- (void) downloadFileFromURL:(NSURL *)url filename:(NSString *)filename cookies:(NSArray <NSHTTPCookie *>*)cookies sender:(nullable id <SEBAbstractBrowserControllerDelegate>)sender;
- (void) fileDownloadedSuccessfully:(NSString *)path;
- (void) conditionallyDownloadAndOpenSEBConfigFromURL:(NSURL *)url;
- (void) openSEBConfigFromData:(NSData *)sebConfigData;
- (void) downloadSEBConfigFileFromURL:(NSURL *)url originalURL:(NSURL *)originalURL cookies:(NSArray <NSHTTPCookie *>*)cookies;
- (void) downloadSEBConfigFileFromURL:(NSURL *)url originalURL:(NSURL *)originalURL cookies:(NSArray <NSHTTPCookie *>*)cookies sender:(nullable id <SEBAbstractBrowserControllerDelegate>)sender;
@property (readonly) BOOL downloadingInTemporaryWebView;

@end


@protocol WKUIDelegatePrivateSEB <NSObject>

typedef NS_OPTIONS(NSUInteger, _WKCaptureDevices) {
    _WKCaptureDeviceMicrophone = 1 << 0,
    _WKCaptureDeviceCamera = 1 << 1,
    _WKCaptureDeviceDisplay = 1 << 2,
};

typedef NS_ENUM(NSInteger, WKDisplayCapturePermissionDecision) {
    WKDisplayCapturePermissionDecisionDeny,
    WKDisplayCapturePermissionDecisionScreenPrompt,
    WKDisplayCapturePermissionDecisionWindowPrompt,
};

- (void)_webView:(WKWebView *)webView requestUserMediaAuthorizationForDevices:(_WKCaptureDevices)devices url:(NSURL *)url mainFrameURL:(NSURL *)mainFrameURL decisionHandler:(void (^)(BOOL authorized))decisionHandler;

- (void)_webView:(WKWebView *)webView requestDisplayCapturePermissionForOrigin:(WKSecurityOrigin *)securityOrigin initiatedByFrame:(WKFrameInfo *)frame withSystemAudio:(BOOL)withSystemAudio decisionHandler:(void (^)(WKDisplayCapturePermissionDecision decision))decisionHandler;

- (void)_webView:(WKWebView *)webView queryPermission:(NSString*)name forOrigin:(WKSecurityOrigin*)origin completionHandler:(void (^)(WKPermissionDecision permissionState))completionHandler API_AVAILABLE(macos(12.0), ios(15.0));

@end


@interface SEBAbstractWebView : NSObject <SEBAbstractBrowserControllerDelegate, SEBAbstractWebViewNavigationDelegate> {
    
@private
    NSString *quitURLTrimmed;
    SEBURLFilter *urlFilter;
}


@property (strong, nonatomic) id<SEBAbstractBrowserControllerDelegate> browserControllerDelegate;
@property (weak, nonatomic) id<SEBAbstractWebViewNavigationDelegate> navigationDelegate;

@property (readwrite) BOOL isMainBrowserWebView;
@property (strong, nonatomic) NSURL *originalURL;
@property (readwrite) BOOL isNavigationAllowed;
@property (readwrite) BOOL isReloadAllowed;
@property (readwrite) BOOL showReloadWarning;
@property (readwrite, nonatomic) BOOL allowSpellCheck;
@property (readwrite, nonatomic) BOOL overrideAllowSpellCheck;
@property (readonly) BOOL downloadPDFFiles;
@property (weak, nonatomic) SEBAbstractWebView *creatingWebView;
@property (strong, nonatomic) NSMutableArray *notAllowedURLs;
@property (readwrite) BOOL dismissAll;


- (instancetype)initNewTabMainWebView:(BOOL)mainWebView
                       withCommonHost:(BOOL)commonHostTab
                        configuration:(WKWebViewConfiguration *)configuration
                   overrideSpellCheck:(BOOL)overrideSpellCheck
                             delegate:(id <SEBAbstractWebViewNavigationDelegate>)delegate;
- (void) initGeneralProperties;

/// The ONE way to put a page-supplied value into a string we hand to
/// -evaluateJavaScript:. Returns a complete JS string literal INCLUDING its
/// surrounding quotes, so call sites interpolate it bare:
///
///     [NSString stringWithFormat:@"foo(%@)", [SEBAbstractWebView blinkeredJSStringLiteral:url]]
///
/// NOT  @"foo('%@')"  — the quotes are already in the literal.
///
/// Hand-rolled escaping is what produced this bug: three conventions grew up in
/// this codebase and two of them were wrong. -focusWindow:/-reloadWindow: escaped
/// `'` but not `\`, so a value ending in a backslash terminated the literal early
/// and everything after it ran as top-level statements in the SHELL's main frame,
/// from any frame of any origin. Serialising as JSON is the same fix Windows
/// already uses (BlinkeredWindowController.cs:641, JsonConvert.SerializeObject).
///
/// Contract: the result is safe to embed in a JavaScript SOURCE context. It is
/// NOT escaped for an HTML context — do not let the receiving JS pass it to
/// innerHTML. Never nil; an unserialisable value fails closed to "".
+ (NSString *) blinkeredJSStringLiteral:(nullable NSString *)value;

/// The general form, for interpolating a whole JSON value (an array of window
/// descriptors, say) rather than a single string. Returns `fallback` verbatim if the
/// object is not JSON-serialisable — pass something inert for the receiving JS, e.g.
/// `@"[]"`. Same JS-source-context contract as above.
+ (NSString *) blinkeredJSLiteral:(nullable id)jsonObject fallback:(NSString *)fallback;

/// THE trusted-origin definition — "is this a document WE served?" — shared by the
/// /seb-quit frame gate here and by SEBBrowserController's bridge gate, so there is ONE
/// definition rather than two that drift (SEB_QUIT_HARDENING_PLAN §3.1, §8.14). The
/// deployment host is derived from the signed config's quit URL, not hardcoded, so
/// staging and self-hosted deployments keep working.
+ (BOOL) blinkeredTrustedOriginHost:(nullable NSString *)host protocol:(nullable NSString *)protocol;

/// Is this navigation THE configured start URL? The whole authorisation for the
/// /seb-setsession and /seb-sethomesession interceptors (§3.3).
+ (BOOL) blinkeredIsConfiguredStartURL:(nullable NSURL *)navigated;

/// The URL -[SEBOSXBrowserController openMainBrowserWindow] actually navigates to, reproducing
/// the startURLAppendQueryParameter append so the comparison and the navigation are the same
/// function of the same inputs. Nil when the config carries no start URL — deliberately NOT
/// falling back to SEBStartPage, since this doubles as the interceptors' trust anchor and a
/// hardcoded constant is not the signed config (OFFLINE_RETRY_DEAD_END_PLAN §3.1).
+ (nullable NSURL *) blinkeredConfiguredStartURL;

/// Where a recovery navigation should go: the committed URL when it is one of ours over https,
/// else the configured start URL, else nil meaning "do nothing". The host test is deliberate —
/// an offline-cover webview holds about:blank, and a mere emptiness test would send a recovery
/// there. Returns one of its arguments by identity, so callers can label the branch by pointer.
/// Pure, so tools/lockdown-tests/run-retry-navigation-test.sh drives the shipped selection
/// directly (OFFLINE_RETRY_DEAD_END_PLAN §3 C4/C5).
+ (nullable NSURL *) blinkeredRecoveryTargetForCommittedURL:(nullable NSURL *)committed
                                         configuredStartURL:(nullable NSURL *)configured;

/// What the /seb-sethomesession interceptor does with its write — the refresh-or-first-write rule
/// (OFFLINE_RETRY_FIX2_G1_REVIEW A8 steelman 2, binding condition 1). Pure, so
/// tools/lockdown-tests/run-home-session-write-guard-test.sh drives the SHIPPED decision.
typedef NS_ENUM(NSInteger, BlinkeredHomeSessionWriteDecision) {
    /// Not the configured start URL — no write, report it, ALLOW the navigation.
    BlinkeredHomeSessionWriteRefuseNotStartURL = 0,
    /// The unlock-window replay: the file is absent because the agent deleted it, and this
    /// process already wrote this session's identity. Skip the write, ALLOW the navigation.
    BlinkeredHomeSessionWriteSkipReplay = 1,
    /// Write it — the file exists (refresh), or this session has not written one yet (create).
    BlinkeredHomeSessionWritePerform = 2,
};

/// The rule, as a pure function of its four inputs. See the comment on the definition.
+ (BlinkeredHomeSessionWriteDecision)
    blinkeredHomeSessionWriteDecisionIsConfiguredStartURL:(BOOL)isConfiguredStartURL
                                               fileExists:(BOOL)fileExists
                                         latchedSessionId:(nullable NSString *)latchedSessionId
                                       candidateSessionId:(nullable NSString *)candidateSessionId;

/// The per-process latch backing clause (b). Nil until this process performs a home-session
/// write; afterwards holds the sessionId written (@"" when the config carries none).
+ (nullable NSString *) blinkeredLatchedHomeSessionId;
/// Arm the latch. Called ONLY after a write that actually landed on disk.
+ (void) blinkeredNoteHomeSessionWritten:(nullable NSString *)sessionId;
/// Disarm it. An in-process session restart begins a session whose first write has not happened.
+ (void) blinkeredResetHomeSessionWriteLatch;

@end


@interface SEBWKNavigationAction : WKNavigationAction

@property (readwrite, nonatomic) WKNavigationType writableNavigationType;
@property (readwrite, nonatomic) NSURLRequest *writableRequest;

@end


@interface SEBNavigationAction : NSObject

@property (readwrite, nonatomic) SEBNavigationActionPolicy policy;
@property (nullable, weak, nonatomic) SEBAbstractWebView *openedWebView;

@end


#if TARGET_OS_OSX
@interface WKPreferences ()

- (void)_setDeveloperExtrasEnabled:(BOOL)developerExtrasEnabled;
- (void)_setShouldAllowUserInstalledFonts:(BOOL)_shouldAllowUserInstalledFonts;
- (void)_setFullScreenEnabled:(BOOL)fullScreenEnabled;
- (void)_setAllowsPictureInPictureMediaPlayback:(BOOL)allowed;

@end
#endif

NS_ASSUME_NONNULL_END

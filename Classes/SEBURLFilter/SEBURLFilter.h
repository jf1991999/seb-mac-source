//
//  SEBURLFilter.h
//  SafeExamBrowser
//
//  Created by Daniel R. Schneider on 06.10.13.
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
#import "SEBURLFilterExpression.h"

NS_ASSUME_NONNULL_BEGIN

@interface SEBURLFilter : NSObject

@property (readwrite) BOOL enableURLFilter;
@property (readwrite) BOOL enableContentFilter;
@property (readwrite) BOOL learningMode;
@property (readwrite) NSInteger urlFilterMessage;
@property (strong) NSMutableArray *permittedList;
@property (strong) NSMutableArray *prohibitedList;
@property (strong) NSMutableArray *ignoreList;
// Blinkered: the FRAME-ONLY allow rules (`frames: "sub"`), each with the top-level pages it may play
// under. One NSDictionary per rule: @"expressions" (the rule's compiled expressions) and @"embedders"
// (its compiled embedder expressions). Never consulted for a main frame or a new window — see
// -testURLAllowed:forSubframe:topLevelURL:.
@property (strong) NSMutableArray<NSDictionary *> *subframePermittedList;
@property (strong, nonatomic) NSArray<NSString*>*regexAllowList;
@property (strong, nonatomic) NSArray<NSString*>*regexBlockList;


+ (SEBURLFilter *) sharedSEBURLFilter;

- (NSError *) updateFilterRulesWithStartURL:(NSURL *)startURL;
- (NSError *) updateFilterRulesSebRules:(BOOL)updateSebRules withStartURL:(NSURL *)startURL;
// Blinkered: rebuild the allow/block lists at runtime from a passed rules array (no NSUserDefaults / no
// re-lock), so the server can push an updated allow-list mid-session. See implementation for details.
- (NSError *) updateFilterRulesWithArray:(NSArray *)URLFilterRules enable:(BOOL)enable startURL:(NSURL *)startURL;

- (NSError *) updateIgnoreRuleList;

- (void) clearIgnoreRuleList;

- (URLFilterRuleActions)testURLAllowed:(NSURL *)URLToFilter;

// Blinkered: the IFRAME question. For a main frame or a new window (forSubframe NO) this is exactly
// -testURLAllowed:. For a sub-frame the frame-only rules are consulted too, but only after the
// ordinary check refused without a block rule, and only when topLevelURL — the COMMITTED page of the
// web view — is http(s) and matches one of the rule's embedders. A nil topLevelURL is untrusted.
- (URLFilterRuleActions)testURLAllowed:(NSURL *)URLToFilter forSubframe:(BOOL)forSubframe topLevelURL:(nullable NSURL *)topLevelURL;

// Blinkered: a rule's `embedders`, compiled — exposed for the gates. Only an array of strings counts;
// anything else is "no embedders". A string that does not compile to an expression WITH A HOST is
// dropped: an expression without one would match every page.
+ (NSArray *)blinkeredCompiledEmbeddersForRule:(NSDictionary *)rule;
- (BOOL)blinkeredTopLevelURL:(nullable NSURL *)topLevelURL matchesEmbedders:(NSArray *)embedders;
// Blinkered: is this a frame-only player that SOME top-level page could admit — i.e. not refused by a
// block rule, and matching a frame-only rule? Only then is there anything for a parent to approve.
- (BOOL)blinkeredURLAwaitsAnEmbedder:(NSURL *)URLToFilter;

- (BOOL) testURLIgnored:(NSURL *)URLToFilter;

- (void) addRuleAction:(URLFilterRuleActions)action withFilterExpression:(SEBURLFilterExpression *)filterExpression;

- (NSArray <NSString*>*)permittedDomains;

@end

NS_ASSUME_NONNULL_END

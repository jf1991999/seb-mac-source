//
//  AboutView.m
//  Safe Exam Browser
//
//  Created by Daniel R. Schneider on 30.10.10.
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

#import "AboutView.h"


@implementation AboutView

- (id)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        // Initialization code here.
    }
    
    return self;
}


- (void)drawRect:(NSRect)dirtyRect {
    NSImage *anImage = [NSImage imageNamed:@"AboutSEB"];

    NSPoint backgroundCenter;
    backgroundCenter.x = [self bounds].size.width / 2;
    backgroundCenter.y = [self bounds].size.height / 2;

    NSPoint drawPoint = backgroundCenter;
    drawPoint.x -= [anImage size].width / 2;
    drawPoint.y -= [anImage size].height / 2;

    [anImage drawAtPoint:drawPoint
                fromRect:NSZeroRect
               operation:NSCompositingOperationSourceOver
                fraction:1.0];

    NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    NSString *versionString = [NSString stringWithFormat:@"Blinkered %@", version ?: @""];
    NSDictionary *attrs = @{
        NSFontAttributeName: [NSFont boldSystemFontOfSize:13],
        NSForegroundColorAttributeName: [NSColor whiteColor],
        NSShadowAttributeName: ({
            NSShadow *s = [[NSShadow alloc] init];
            s.shadowColor = [NSColor colorWithCalibratedWhite:0 alpha:0.7];
            s.shadowOffset = NSMakeSize(0, -1);
            s.shadowBlurRadius = 3;
            s;
        })
    };
    // Draw version in the top-left corner of the visible view area
    CGFloat viewHeight = [self bounds].size.height;
    [versionString drawAtPoint:NSMakePoint(14, viewHeight - 24)
                withAttributes:attrs];

    // SEB attribution (MPL 2.0 §3.4 — the rebrand removed the About credits; restored here).
    // Small type, bottom of the view, matching the version's white-with-shadow style.
    NSString *attribution =
        @"Based on Safe Exam Browser, Copyright (c) 2010-2025 Daniel R. Schneider, "
         "ETH Zurich, IT Services, based on the original idea of Safe Exam Browser by "
         "Stefan Schneider, University of Giessen.\n"
         "Modified SEB source: https://github.com/jf1991999/seb-mac-source\n"
         "Licence: MPL 2.0 - see LICENCE in this application's Resources.";
    NSMutableParagraphStyle *para = [[NSMutableParagraphStyle alloc] init];
    para.alignment = NSTextAlignmentLeft;
    para.lineBreakMode = NSLineBreakByWordWrapping;
    NSDictionary *attribAttrs = @{
        NSFontAttributeName: [NSFont systemFontOfSize:9],
        NSForegroundColorAttributeName: [NSColor colorWithCalibratedWhite:1.0 alpha:0.85],
        NSParagraphStyleAttributeName: para,
        NSShadowAttributeName: ({
            NSShadow *s = [[NSShadow alloc] init];
            s.shadowColor = [NSColor colorWithCalibratedWhite:0 alpha:0.7];
            s.shadowOffset = NSMakeSize(0, -1);
            s.shadowBlurRadius = 2;
            s;
        })
    };
    CGFloat pad = 12;
    NSRect attribRect = NSMakeRect(pad, pad, [self bounds].size.width - 2 * pad, 64);
    [attribution drawInRect:attribRect withAttributes:attribAttrs];
}

@end

//
//  AboutWindow.m
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

#import "AboutWindow.h"

@implementation AboutWindow

- (void) awakeFromNib
{
    // Remove the old SEB version label and copyright scroll view — version is drawn
    // directly onto the mascot image by AboutView drawRect:. Removing (not hiding)
    // them also drops their layout constraints, which compressed the window to
    // 440×300 and cropped the 440×440 mascot image.
    [copyright.enclosingScrollView removeFromSuperview];
    [version removeFromSuperview];
    // The splash appears/disappears in place during the launch sequence — no zoom/fade.
    self.animationBehavior = NSWindowAnimationBehaviorNone;
}


// Overriding this method to return NO prevents that the Preferences Window
// looses key state when the About Window is opened
- (BOOL)canBecomeKeyWindow
{
    return NO;
}


// When clicked into the window, close it!
- (void)mouseDown:(NSEvent *)theEvent {
	[self orderOut:self];
    [[NSApplication sharedApplication] stopModal];
}


@end

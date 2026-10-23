#import <UIKit/UIKit.h>

// Placeholder redirect library: no functional hooks yet.
%hook UIView
- (void)setHidden:(BOOL)hidden {
    %orig;
}
%end

__attribute__((constructor))
static void contraredirect_init(void) {
}

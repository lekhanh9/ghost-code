#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSLog(@"contrainstalld placeholder daemon started");
    }
    dispatch_main();
    return 0;
}

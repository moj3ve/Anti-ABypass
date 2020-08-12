#import "JailbreakDetection.h"
#include <dlfcn.h>
#include <sys/syscall.h>
#include <mach-o/dyld.h>



@implementation JailbreakDetection

+(BOOL)isJailbreak{
    JailbreakDetection *check = [[JailbreakDetection alloc] init];
    if ([check check_file] || [check check_inject] || [check check_class] || [check check_dyld]){
        return true;
    }
    return false;
}

-(BOOL)check_dyld
{
    uint32_t count = _dyld_image_count();
    Dl_info dylib_info;
    for(uint32_t i = 0; i < count; i++) {
        dladdr(_dyld_get_image_header(i), &dylib_info);
        if([[NSString stringWithUTF8String:dylib_info.dli_fname] containsString:@"ABypass"]) {
            NSLog(@"[Anti] Detected ABypass dylib!!!");
            return true;
        }
    }
    return false;
}

-(BOOL)check_file
{
    if(syscall(SYS_access, "///././Library//./MobileSubstrate///DynamicLibraries///././/!ABypass2.dylib", F_OK) == -1) {
        return false;
    }
    NSLog(@"[Anti] Detected ABypass file!!!");
    return true;
}

-(BOOL)check_class
{
    if (NSClassFromString(@"AQPattern")) {
        NSLog(@"[Anti] Detected ABypass class!!!");
        return true;
    }
    return false;
}

-(BOOL)check_inject
{
    //dlsym detection
    void* dlpoint = dlsym((void *)RTLD_DEFAULT, "_Z12hookingSVC80v");
    if(dlpoint != 0x0) {
        NSLog(@"[Anti] Detected dlsym: ABypass hookingSVC80: %p", dlpoint);
        return true;
    }
    return false;
}

@end

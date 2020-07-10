//
//  main.m
//  asn1decoder
//
//  Created by lovecode666 on 2020/7/9.
//  Copyright © 2020 mll<coleflowersma#gmail.com> All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Parser.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            printf("%s derfile\n", argv[0]);
            return 1;
        }
        printf("Parsing:%s\n", argv[1]);
        Parser *parser = [[Parser alloc] initWithPath:[NSString stringWithUTF8String:argv[1]]];
        BOOL decRes = [parser decode];
        if (decRes) {
            NSDictionary *data = [parser getDec];
            printf("Parsed:%s\n", [[data description] UTF8String]);
        } else {
            printf("Parse faile\n");
        }
    }
    return 0;
}

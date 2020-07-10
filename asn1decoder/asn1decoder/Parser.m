//
//  Parser.m
//  asn1decoder
//
//  Created by lovecode666 on 2020/7/9.
//  Copyright © 2020 mll<coleflowersma#gmail.com> All rights reserved.
//

#import "Parser.h"
#import <Security/Security.h>
#import <Security/SecAsn1Coder.h>
#import <Security/SecAsn1Templates.h>

typedef struct
{
    size_t          length;
    unsigned char   *data;
} ASN1_Data;

typedef struct
{
    ASN1_Data idname;
    ASN1_Data val;
} Attr_Item;

typedef struct
{
    Attr_Item *obj;
} Attr_SET;

typedef struct
{
    Attr_SET *a1;
    Attr_SET *a2;
    Attr_SET *a3;
    Attr_SET *a4;
    Attr_SET *a5;
    Attr_SET *a6;
    Attr_SET *a7;
} ReceiptPayloadTotal;

static const SecAsn1Template kATemplate[] =
{
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(Attr_Item) },
    { SEC_ASN1_OBJECT_ID, offsetof(Attr_Item, idname), NULL, 0 },
    { SEC_ASN1_PRINTABLE_STRING, offsetof(Attr_Item, val), NULL, 0 },
    { 0, 0, NULL, 0 }
};
static const SecAsn1Template kUTF8Template[] =
{
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(Attr_Item) },
    { SEC_ASN1_OBJECT_ID, offsetof(Attr_Item, idname), NULL, 0 },
    { SEC_ASN1_UTF8_STRING, offsetof(Attr_Item, val), NULL, 0 },
    { 0, 0, NULL, 0 }
};
static const SecAsn1Template kGTemplate[] =
{
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(Attr_Item) },
    { SEC_ASN1_OBJECT_ID, offsetof(Attr_Item, idname), NULL, 0 },
    { SEC_ASN1_IA5_STRING, offsetof(Attr_Item, val), NULL, 0 },
    { 0, 0, NULL, 0 }
};

static const SecAsn1Template kTpl[] =
{
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ReceiptPayloadTotal)},
    { SEC_ASN1_SET_OF, offsetof(ReceiptPayloadTotal, a1), kATemplate, 0 },
    { SEC_ASN1_SET_OF, offsetof(ReceiptPayloadTotal, a2), kUTF8Template, 0 },
    { SEC_ASN1_SET_OF, offsetof(ReceiptPayloadTotal, a3), kUTF8Template, 0 },
    { SEC_ASN1_SET_OF, offsetof(ReceiptPayloadTotal, a4), kUTF8Template, 0 },
    { SEC_ASN1_SET_OF, offsetof(ReceiptPayloadTotal, a5), kUTF8Template, 0 },
    { SEC_ASN1_SET_OF, offsetof(ReceiptPayloadTotal, a6), kUTF8Template, 0 },
    { SEC_ASN1_SET_OF, offsetof(ReceiptPayloadTotal, a7), kGTemplate, 0 },
    
    { 0, 0, NULL, 0 }
};

@interface Parser()

@property (nonatomic, strong) NSData *data;

@property (nonatomic, strong) NSDictionary *dec;

@end

@implementation Parser

- (instancetype)initWithPath:(NSString *)path {
    self = [super init];
    
    self.data = [[NSData alloc] initWithContentsOfFile:path];
    
    return self;
}

- (BOOL)decode {
    if (!self.data || self.data.length == 0) {
        return NO;
    }

    SecAsn1CoderRef decoder = NULL;
    OSStatus status = -1;
    ReceiptPayloadTotal payload = {0};
    Attr_SET *attribute;
    
    status = SecAsn1CoderCreate(&decoder);
    if (status != noErr) {
        NSLog(@"create faile");
        return NO;
    }
    
    status = SecAsn1Decode(decoder, self.data.bytes, self.data.length, kTpl, &payload);
    if (status != noErr) {
        NSError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        
        NSLog(@"decode faile %@ ", error);
        return NO;
    }
    
    NSMutableDictionary *dec = @{}.mutableCopy;
    [dec setValue:[self parseData:payload.a1->obj->val.data] forKey:@"countryName"];
    [dec setValue:[self parseData:payload.a2->obj->val.data] forKey:@"stateOrProvinceName"];
    [dec setValue:[self parseData:payload.a3->obj->val.data] forKey:@"localityName"];
    [dec setValue:[self parseData:payload.a4->obj->val.data] forKey:@"organizationName"];
    [dec setValue:[self parseData:payload.a5->obj->val.data] forKey:@"organizationalUnitName"];
    [dec setValue:[self parseData:payload.a6->obj->val.data] forKey:@"commonName"];
    [dec setValue:[self parseData:payload.a7->obj->val.data] forKey:@"emailAddress"];
     
    self.dec = dec.copy;
    
    return YES;
}

- (NSString *)parseData:(unsigned char *)data {
    return [NSString stringWithUTF8String:(const char *)data];
}

- (NSDictionary *)getDec {
    return self.dec;
}

@end

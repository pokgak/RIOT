/* Created from wolfssl-examples test certificate+key, 08/08/2019 */
const unsigned char server_cert[] = {
  0x30, 0x82, 0x03, 0x50, 0x30, 0x82, 0x02, 0xf5, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x02, 0x10, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x81, 0x97, 0x31, 0x0b, 0x30, 0x09,
  0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30,
  0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68,
  0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
  0x55, 0x04, 0x07, 0x0c, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6c, 0x65,
  0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x77,
  0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
  0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x44, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70,
  0x6d, 0x65, 0x6e, 0x74, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
  0x03, 0x0c, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x77, 0x6f, 0x6c, 0x66, 0x73,
  0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69,
  0x6e, 0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e,
  0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x31, 0x30, 0x32,
  0x30, 0x31, 0x38, 0x31, 0x39, 0x30, 0x36, 0x5a, 0x17, 0x0d, 0x32, 0x37,
  0x31, 0x30, 0x31, 0x38, 0x31, 0x38, 0x31, 0x39, 0x30, 0x36, 0x5a, 0x30,
  0x81, 0x8f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
  0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
  0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e,
  0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x53,
  0x65, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
  0x55, 0x04, 0x0a, 0x0c, 0x07, 0x45, 0x6c, 0x69, 0x70, 0x74, 0x69, 0x63,
  0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x45,
  0x43, 0x43, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
  0x0f, 0x77, 0x77, 0x77, 0x2e, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c,
  0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6e, 0x66,
  0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f,
  0x6d, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
  0x03, 0x42, 0x00, 0x04, 0xbb, 0x33, 0xac, 0x4c, 0x27, 0x50, 0x4a, 0xc6,
  0x4a, 0xa5, 0x04, 0xc3, 0x3c, 0xde, 0x9f, 0x36, 0xdb, 0x72, 0x2d, 0xce,
  0x94, 0xea, 0x2b, 0xfa, 0xcb, 0x20, 0x09, 0x39, 0x2c, 0x16, 0xe8, 0x61,
  0x02, 0xe9, 0xaf, 0x4d, 0xd3, 0x02, 0x93, 0x9a, 0x31, 0x5b, 0x97, 0x92,
  0x21, 0x7f, 0xf0, 0xcf, 0x18, 0xda, 0x91, 0x11, 0x02, 0x34, 0x86, 0xe8,
  0x20, 0x58, 0x33, 0x0b, 0x80, 0x34, 0x89, 0xd8, 0xa3, 0x82, 0x01, 0x35,
  0x30, 0x82, 0x01, 0x31, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04,
  0x02, 0x30, 0x00, 0x30, 0x11, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86,
  0xf8, 0x42, 0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x06, 0x40, 0x30, 0x1d,
  0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x5d, 0x5d, 0x26,
  0xef, 0xac, 0x7e, 0x36, 0xf9, 0x9b, 0x76, 0x15, 0x2b, 0x4a, 0x25, 0x02,
  0x23, 0xef, 0xb2, 0x89, 0x30, 0x30, 0x81, 0xcc, 0x06, 0x03, 0x55, 0x1d,
  0x23, 0x04, 0x81, 0xc4, 0x30, 0x81, 0xc1, 0x80, 0x14, 0x56, 0x8e, 0x9a,
  0xc3, 0xf0, 0x42, 0xde, 0x18, 0xb9, 0x45, 0x55, 0x6e, 0xf9, 0x93, 0xcf,
  0xea, 0xc3, 0xf3, 0xa5, 0x21, 0xa1, 0x81, 0x9d, 0xa4, 0x81, 0x9a, 0x30,
  0x81, 0x97, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
  0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
  0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e,
  0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x53,
  0x65, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
  0x55, 0x04, 0x0a, 0x0c, 0x07, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c,
  0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x44,
  0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x6d, 0x65, 0x6e, 0x74, 0x31, 0x18,
  0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x77, 0x77,
  0x2e, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d,
  0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x77, 0x6f,
  0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x09, 0x00,
  0x97, 0xb4, 0xbd, 0x16, 0x78, 0xf8, 0x47, 0xf2, 0x30, 0x0e, 0x06, 0x03,
  0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x03, 0xa8,
  0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06,
  0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x0a, 0x06,
  0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00,
  0x30, 0x46, 0x02, 0x21, 0x00, 0xbe, 0xb8, 0x58, 0xf0, 0xe4, 0x15, 0x01,
  0x1f, 0xdf, 0x70, 0x54, 0x73, 0x4a, 0x6c, 0x40, 0x1f, 0x77, 0xa8, 0xb4,
  0xeb, 0x52, 0x1e, 0xbf, 0xf5, 0x0d, 0xb1, 0x33, 0xca, 0x6a, 0xc4, 0x76,
  0xb9, 0x02, 0x21, 0x00, 0x97, 0x08, 0xde, 0x2c, 0x28, 0xc1, 0x45, 0x71,
  0xb6, 0x2c, 0x54, 0x87, 0x98, 0x63, 0x76, 0xa8, 0x21, 0x34, 0x90, 0xa8,
  0xf7, 0x9e, 0x3f, 0xfc, 0x02, 0xb0, 0xe7, 0xd3, 0x09, 0x31, 0x27, 0xe4
};
unsigned int server_cert_len = 852;
const unsigned char server_key[] = {
  0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x45, 0xb6, 0x69, 0x02, 0x73,
  0x9c, 0x6c, 0x85, 0xa1, 0x38, 0x5b, 0x72, 0xe8, 0xe8, 0xc7, 0xac, 0xc4,
  0x03, 0x8d, 0x53, 0x35, 0x04, 0xfa, 0x6c, 0x28, 0xdc, 0x34, 0x8d, 0xe1,
  0xa8, 0x09, 0x8c, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xbb, 0x33, 0xac,
  0x4c, 0x27, 0x50, 0x4a, 0xc6, 0x4a, 0xa5, 0x04, 0xc3, 0x3c, 0xde, 0x9f,
  0x36, 0xdb, 0x72, 0x2d, 0xce, 0x94, 0xea, 0x2b, 0xfa, 0xcb, 0x20, 0x09,
  0x39, 0x2c, 0x16, 0xe8, 0x61, 0x02, 0xe9, 0xaf, 0x4d, 0xd3, 0x02, 0x93,
  0x9a, 0x31, 0x5b, 0x97, 0x92, 0x21, 0x7f, 0xf0, 0xcf, 0x18, 0xda, 0x91,
  0x11, 0x02, 0x34, 0x86, 0xe8, 0x20, 0x58, 0x33, 0x0b, 0x80, 0x34, 0x89,
  0xd8
};
unsigned int server_key_len = 121;

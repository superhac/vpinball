/*** Autogenerated by WIDL 10.2 from B2S.idl - Do not edit ***/

#include <rpc.h>
#include <rpcndr.h>

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
    DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

#elif defined(__cplusplus)

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
    EXTERN_C const type DECLSPEC_SELECTANY name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#else

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
    const type DECLSPEC_SELECTANY name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#endif

#ifdef __cplusplus
extern "C" {
#endif

MIDL_DEFINE_GUID(IID, LIBID_B2SBackglassServer, 0x4e596935, 0xcb6b, 0x40d8, 0x81,0xf9, 0x42,0x83,0x97,0xc6,0x54,0xcf);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SAnimation, 0x703807b5, 0x9dc2, 0x3789, 0x9e,0x80, 0x4f,0xc1,0x98,0xaa,0xed,0x4e);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SCollectData, 0xe575e3c7, 0xe580, 0x3749, 0x88,0x17, 0x01,0x17,0x03,0xfd,0x76,0xc8);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SData, 0x59e7d353, 0x6d58, 0x37b3, 0xae,0xe6, 0x2b,0xea,0xfa,0x1c,0x43,0x54);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SLED, 0xbb2907ec, 0x86b7, 0x3fc6, 0x95,0x67, 0x55,0x6d,0xe0,0x3a,0x24,0xd5);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SPlayer, 0x155b2de6, 0x38f5, 0x369c, 0xba,0x2f, 0x31,0xbe,0xda,0xed,0x1f,0x60);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SReelDisplay, 0x015c0c18, 0xb2cb, 0x3fb2, 0x9c,0xce, 0x1b,0xda,0xa9,0x32,0x9e,0xcf);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SScreen, 0x2e929b95, 0x1121, 0x3e5d, 0x82,0x71, 0xc1,0x58,0xdd,0x7f,0xc3,0xbc);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SSettings, 0xdc1d1c65, 0x9bef, 0x389b, 0x97,0x51, 0x3f,0x0f,0xe9,0x21,0x69,0x3b);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SStatistics, 0x9674feda, 0x91ba, 0x3a48, 0x96,0xd9, 0x9d,0xb1,0xf4,0x1f,0x24,0x85);
MIDL_DEFINE_GUID(CLSID, CLSID_Processes, 0xbb2cc0ce, 0x0927, 0x32f5, 0xba,0x09, 0x7f,0xc0,0xe0,0x67,0x15,0xdf);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SBaseBox, 0xf278af37, 0x7a8d, 0x37f6, 0x96,0x34, 0xfc,0x9b,0x29,0xa1,0x0a,0xd3);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SLEDBox, 0x8293c4f8, 0xfa8a, 0x3980, 0x90,0x58, 0x10,0x2c,0x9a,0x3b,0x24,0xb1);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SPictureBox, 0xf5323223, 0xb199, 0x35d7, 0x9e,0x12, 0xdb,0xed,0x2c,0xf0,0xcc,0x4e);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SReelBox, 0x4d78c14d, 0xc1ea, 0x36a6, 0xa4,0x8f, 0x29,0x78,0x7b,0xf7,0xda,0x17);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SSnifferPanel, 0xb86f0ed8, 0xc18c, 0x3b7c, 0xae,0x0d, 0xa1,0xb9,0xcd,0x46,0x19,0x0d);
MIDL_DEFINE_GUID(CLSID, CLSID_Dream7Display, 0x52089ee8, 0xd61f, 0x3429, 0xa8,0x57, 0xe1,0xaa,0x08,0xfb,0xef,0xa1);
MIDL_DEFINE_GUID(CLSID, CLSID_formBackglass, 0x41e018de, 0xade2, 0x3d8f, 0x97,0xb4, 0x38,0x2f,0x88,0xfc,0x55,0x3b);
MIDL_DEFINE_GUID(CLSID, CLSID_formDMD, 0x22e7ab66, 0xf194, 0x3512, 0xa6,0x1e, 0x0e,0xf0,0x52,0xcf,0x53,0x42);
MIDL_DEFINE_GUID(CLSID, CLSID_formMode, 0xbabcc6bd, 0x6710, 0x3554, 0x9d,0xd3, 0xb4,0x0f,0xf0,0x86,0xfc,0xf9);
MIDL_DEFINE_GUID(CLSID, CLSID_formSettings, 0x74a040be, 0x21b4, 0x3ff9, 0x89,0xc3, 0x09,0x25,0xe2,0x18,0xf1,0x25);
MIDL_DEFINE_GUID(CLSID, CLSID_formSettingsMore, 0xf36a696b, 0x15d6, 0x338d, 0x9f,0x22, 0x94,0xc9,0x34,0x2b,0x1c,0x60);
MIDL_DEFINE_GUID(CLSID, CLSID_Statistics, 0xb550eb0d, 0x886e, 0x3d1c, 0x82,0xcd, 0xbf,0x5a,0x58,0xd1,0x17,0x57);
MIDL_DEFINE_GUID(CLSID, CLSID_Log, 0x0e21f7b4, 0x601b, 0x3052, 0xb9,0xcd, 0x4b,0x7c,0x42,0x57,0x8c,0x90);
MIDL_DEFINE_GUID(CLSID, CLSID_Plugin, 0x2d89ece4, 0xba92, 0x345c, 0x98,0xdc, 0xa7,0xbc,0x20,0xe9,0xe8,0xff);
MIDL_DEFINE_GUID(CLSID, CLSID_PluginHost, 0x7622de45, 0x3760, 0x3569, 0xa6,0x34, 0xca,0xf9,0x06,0x3b,0x6d,0x16);
MIDL_DEFINE_GUID(CLSID, CLSID_PluginList, 0xac12a926, 0x813f, 0x3843, 0xae,0x67, 0x0a,0x1e,0x3f,0x6d,0xb8,0x42);
MIDL_DEFINE_GUID(CLSID, CLSID_PluginWindow, 0xd7261b20, 0xa7be, 0x3254, 0xb4,0xae, 0x00,0x8e,0x55,0x1a,0x27,0x2b);
MIDL_DEFINE_GUID(CLSID, CLSID_Server, 0x09e233a3, 0xcc79, 0x457a, 0xb4,0x9e, 0xf6,0x37,0x58,0x88,0x91,0xe5);
MIDL_DEFINE_GUID(CLSID, CLSID_B2SAnimationBase, 0x79602b83, 0xebde, 0x366c, 0x93,0x59, 0x80,0x0f,0x4f,0x6c,0x7d,0xce);
MIDL_DEFINE_GUID(CLSID, CLSID_TimerAnimation, 0x285aaa5b, 0xb3d2, 0x3a52, 0xa2,0x1c, 0x19,0x10,0x08,0x34,0xf9,0x81);
MIDL_DEFINE_GUID(CLSID, CLSID_PictureBoxAnimation, 0xc5fbe4b8, 0xeb11, 0x3828, 0xab,0x1a, 0x52,0xf7,0x60,0xad,0x8f,0x6a);
MIDL_DEFINE_GUID(CLSID, CLSID_PictureBoxAnimationEntry, 0x17b5f964, 0x5ce8, 0x32a3, 0x87,0xef, 0xd0,0xde,0xe6,0x6b,0x2d,0x5e);
MIDL_DEFINE_GUID(CLSID, CLSID_PictureBoxAnimationCollection, 0x374f2f95, 0x2c4b, 0x35a9, 0x98,0xdc, 0x0b,0xc5,0x83,0xab,0xec,0xb9);
MIDL_DEFINE_GUID(CLSID, CLSID_PictureBoxAnimationCollectionEntry, 0x6c3ddcd4, 0x8003, 0x3c2a, 0xa9,0x03, 0x10,0x10,0xe4,0x8f,0xc2,0x24);
MIDL_DEFINE_GUID(CLSID, CLSID_CollectData, 0x689eac8e, 0x9138, 0x310b, 0xb3,0x7e, 0x69,0x0c,0xef,0x21,0xeb,0xff);
MIDL_DEFINE_GUID(CLSID, CLSID_PictureBoxCollection, 0x4752d05a, 0xf95e, 0x348e, 0x8e,0xf8, 0x05,0x21,0xf6,0x29,0xcb,0xd2);
MIDL_DEFINE_GUID(CLSID, CLSID_ReelBoxCollection, 0xe829e1d3, 0x1aec, 0x3ac4, 0xb6,0x23, 0x3a,0x38,0x6d,0x62,0xda,0x80);
MIDL_DEFINE_GUID(CLSID, CLSID_ZOrderCollection, 0x6019c772, 0x1c73, 0x3d75, 0xbe,0x91, 0x54,0xd1,0x0c,0x6e,0x46,0xef);
MIDL_DEFINE_GUID(CLSID, CLSID_AnimationInfo, 0x0b42cd23, 0x99a8, 0x37f1, 0x82,0x46, 0xd6,0x12,0x50,0x3c,0x22,0xba);
MIDL_DEFINE_GUID(CLSID, CLSID_AnimationCollection, 0x24607c71, 0x413f, 0x3ec5, 0xa3,0x9c, 0x05,0x6e,0xfe,0x92,0x6e,0xc0);
MIDL_DEFINE_GUID(CLSID, CLSID_IlluminationGroupCollection, 0x92390d93, 0xa2f2, 0x3591, 0xb4,0x7c, 0xbe,0x48,0x85,0x1c,0x42,0xad);
MIDL_DEFINE_GUID(CLSID, CLSID_LEDAreaInfo, 0x3d38e61e, 0x1540, 0x3b1a, 0x89,0x51, 0x4a,0x90,0x81,0xb6,0xdc,0x01);
MIDL_DEFINE_GUID(CLSID, CLSID_LEDDisplayDigitLocation, 0x3689038e, 0x7a56, 0x319f, 0x86,0x98, 0x89,0x50,0xa3,0x2b,0xc2,0xc2);
MIDL_DEFINE_GUID(CLSID, CLSID_ControlCollection, 0xa8138c07, 0x892e, 0x36bc, 0xb9,0x11, 0xb9,0x61,0x5d,0x8c,0xff,0x76);
MIDL_DEFINE_GUID(CLSID, CLSID_ControlInfo, 0x1bfdfd06, 0x8e67, 0x34b0, 0xa0,0x8d, 0xab,0xc4,0x37,0x13,0x64,0xa7);
MIDL_DEFINE_GUID(CLSID, CLSID_StatsCollection, 0x0671e2a7, 0xced6, 0x380a, 0xa5,0xc7, 0xa2,0x8b,0xd2,0x4a,0x64,0x9e);
MIDL_DEFINE_GUID(CLSID, CLSID_StatsEntry, 0xd7e864cc, 0x5ba3, 0x3376, 0x8a,0xe5, 0xca,0xae,0xa0,0xde,0xb2,0xac);
MIDL_DEFINE_GUID(CLSID, CLSID_ReelRollOverEventArgs, 0xebe204ce, 0x785f, 0x366a, 0x9d,0x64, 0x58,0x31,0x48,0x74,0xac,0x25);
MIDL_DEFINE_GUID(CLSID, CLSID_ReelRollOverEventHandler, 0xbaaa5d5d, 0x630a, 0x3c7a, 0xaa,0x4d, 0x6e,0x32,0x9b,0x73,0xbc,0x88);
MIDL_DEFINE_GUID(IID, IID__Server, 0x5693c68c, 0x5834, 0x466d, 0xaa,0xac, 0xa8,0x69,0x22,0x07,0x6e,0xfd);
MIDL_DEFINE_GUID(CLSID, CLSID_FinishedEventHandler, 0xa82ba555, 0x5bec, 0x31f2, 0xa8,0x0b, 0x30,0x0b,0x5e,0xc3,0x89,0x3d);
MIDL_DEFINE_GUID(CLSID, CLSID_ReelBoxCollection_2, 0xf31f135a, 0x82f9, 0x3858, 0xa0,0xc1, 0x9c,0x54,0xdd,0xf2,0xbb,0xcd);
MIDL_DEFINE_GUID(CLSID, CLSID_FinishedEventHandler_2, 0xd47f6892, 0x58d3, 0x3c89, 0xb3,0x71, 0x88,0x18,0x33,0x4e,0xe9,0xde);
MIDL_DEFINE_GUID(IID, IID__B2SAnimation, 0xbb3a6d69, 0xc0db, 0x3357, 0xb8,0x6b, 0x77,0x66,0x5a,0x72,0x2f,0x6c);
MIDL_DEFINE_GUID(IID, IID__B2SData, 0xb051b2dd, 0xfcfd, 0x3698, 0xaf,0x6c, 0x75,0xbb,0xb1,0xe1,0x27,0x61);
MIDL_DEFINE_GUID(IID, IID__B2SLED, 0x9afc80dc, 0xd8c5, 0x3754, 0x8c,0xfd, 0xf6,0xac,0x2f,0xe2,0x6e,0xca);
MIDL_DEFINE_GUID(IID, IID__B2SReelDisplay, 0x447cd217, 0x5bce, 0x3eb1, 0xb0,0x6d, 0xda,0x4f,0x70,0x99,0x28,0x24);
MIDL_DEFINE_GUID(IID, IID__B2SScreen, 0x8a67a0f0, 0x75cd, 0x3b0d, 0x9b,0xbd, 0x3c,0xd9,0xf9,0x9a,0x30,0xa6);
MIDL_DEFINE_GUID(IID, IID__B2SSettings, 0x64b1444f, 0x9b3e, 0x37c0, 0x91,0x57, 0xbf,0xc6,0x30,0x19,0x09,0xa0);
MIDL_DEFINE_GUID(IID, IID__B2SStatistics, 0x0d85db55, 0xe28c, 0x3165, 0xb9,0xd0, 0xe4,0xc5,0xec,0xf2,0x70,0x1a);
MIDL_DEFINE_GUID(IID, IID__Processes, 0x23b8880a, 0xdb20, 0x3b4b, 0x96,0xb6, 0xa0,0x31,0x38,0xf9,0xff,0x73);
MIDL_DEFINE_GUID(IID, IID__B2SBaseBox, 0xd8774a88, 0x6c6a, 0x338c, 0xba,0xd1, 0x59,0x26,0xf0,0xba,0x05,0x1f);
MIDL_DEFINE_GUID(IID, IID__B2SLEDBox, 0xdeef2d0b, 0x84f6, 0x35b5, 0x94,0xff, 0x68,0xe2,0x30,0x87,0x7c,0x2e);
MIDL_DEFINE_GUID(IID, IID__B2SPictureBox, 0xb47357b4, 0xcb2e, 0x3a74, 0xac,0xf9, 0x96,0x05,0xbc,0x0b,0xfc,0x4e);
MIDL_DEFINE_GUID(IID, IID__B2SReelBox, 0xabe7c98b, 0xe450, 0x3cce, 0xa5,0x14, 0xb3,0x84,0xe4,0x03,0xeb,0xe9);
MIDL_DEFINE_GUID(IID, IID__B2SSnifferPanel, 0xdfd89246, 0x85db, 0x325c, 0x8e,0x7e, 0xc7,0x86,0x94,0xb0,0xbc,0xc3);
MIDL_DEFINE_GUID(IID, IID__Dream7Display, 0xf104b349, 0x4715, 0x3831, 0xb5,0x68, 0xd0,0x5f,0x67,0x30,0x1a,0x0e);
MIDL_DEFINE_GUID(IID, IID__formBackglass, 0xb617ad73, 0x9f14, 0x3834, 0xad,0x53, 0x2c,0xf2,0x01,0xb9,0x6a,0xae);
MIDL_DEFINE_GUID(IID, IID__formDMD, 0x4d0ce464, 0x1727, 0x3de8, 0x9c,0x81, 0xf3,0x6b,0x9e,0x84,0xc6,0xbc);
MIDL_DEFINE_GUID(IID, IID__formMode, 0xba3c57df, 0xab86, 0x3f41, 0xa1,0xe6, 0x81,0xb6,0xf7,0x70,0xbd,0x4c);
MIDL_DEFINE_GUID(IID, IID__formSettings, 0x74f1bc23, 0x3701, 0x3022, 0x9c,0xb7, 0xde,0xc7,0xe7,0xb7,0x9a,0x79);
MIDL_DEFINE_GUID(IID, IID__formSettingsMore, 0xfbbc52ac, 0xe4d5, 0x3966, 0x96,0xc1, 0x41,0x8b,0x13,0xc6,0x80,0xf4);
MIDL_DEFINE_GUID(IID, IID__Statistics, 0x601025c2, 0xcd71, 0x3c29, 0x8d,0xe9, 0x8a,0xc2,0x42,0x7d,0x5d,0x4a);
MIDL_DEFINE_GUID(IID, IID__Log, 0xb48d5fc4, 0x0896, 0x35cf, 0xbd,0xa2, 0x02,0x5d,0xd7,0xc6,0x4c,0x27);
MIDL_DEFINE_GUID(IID, IID__Plugin, 0xba321893, 0x568b, 0x3ddf, 0xb4,0xe2, 0x15,0x4a,0x34,0x31,0x56,0xf3);
MIDL_DEFINE_GUID(IID, IID__PluginHost, 0xaabb1d6c, 0x6c19, 0x385e, 0x86,0x9f, 0xe4,0x18,0xd9,0xde,0xa7,0xf8);
MIDL_DEFINE_GUID(IID, IID__PluginWindow, 0xebe49d74, 0x2985, 0x382d, 0x93,0xa4, 0x09,0x53,0x9a,0xfc,0xbb,0x5b);
MIDL_DEFINE_GUID(IID, IID__B2SAnimationBase, 0x93a9db8d, 0xfddf, 0x37c2, 0x8d,0x9f, 0x5e,0xba,0x58,0x7c,0x69,0x15);
MIDL_DEFINE_GUID(IID, IID__TimerAnimation, 0xf8efe9de, 0xbc50, 0x3fe6, 0x92,0x4c, 0x66,0xf8,0x0c,0x7d,0xcd,0xb2);
MIDL_DEFINE_GUID(IID, IID__PictureBoxAnimation, 0x9c808d89, 0xdea5, 0x3df3, 0x93,0x95, 0xc1,0x5b,0xa5,0x20,0x0c,0xd3);
MIDL_DEFINE_GUID(IID, IID__PictureBoxAnimationEntry, 0x472f1c42, 0xb9f5, 0x397f, 0xac,0x93, 0x25,0x14,0xc7,0x19,0x31,0xfa);
MIDL_DEFINE_GUID(IID, IID__PictureBoxAnimationCollection, 0xb2d80ba2, 0xd58b, 0x339f, 0xb7,0x8c, 0x0e,0x30,0x75,0xaa,0x40,0x2b);
MIDL_DEFINE_GUID(IID, IID__PictureBoxAnimationCollectionEntry, 0x00af4eb2, 0x9009, 0x36a6, 0x8d,0x37, 0x1c,0x11,0x06,0xdd,0x8c,0xb5);
MIDL_DEFINE_GUID(IID, IID__CollectData, 0xe08dd18a, 0x3637, 0x3f50, 0xa2,0xad, 0x39,0xc1,0xdd,0x9f,0xc7,0x85);
MIDL_DEFINE_GUID(IID, IID__AnimationInfo, 0xad63a63e, 0xa903, 0x39b6, 0xb4,0x39, 0xc8,0xb9,0xe3,0x4a,0xb8,0xc2);
MIDL_DEFINE_GUID(IID, IID__LEDAreaInfo, 0x9df0641c, 0xaedc, 0x3263, 0x8f,0xd3, 0xa0,0x89,0x53,0x45,0xe2,0xc2);
MIDL_DEFINE_GUID(IID, IID__LEDDisplayDigitLocation, 0x5329bff0, 0xf0e3, 0x390f, 0x92,0xbe, 0x9f,0x02,0x0f,0x52,0x02,0xf2);
MIDL_DEFINE_GUID(IID, IID__ControlInfo, 0x233c5bfa, 0xee42, 0x3b02, 0xa5,0x8d, 0x87,0x31,0x9d,0xc7,0xa8,0x33);
MIDL_DEFINE_GUID(IID, IID__StatsCollection, 0x0cace85a, 0x354b, 0x3a04, 0xbf,0x4e, 0xc1,0x10,0x9d,0xf4,0x5c,0xa7);
MIDL_DEFINE_GUID(IID, IID__StatsEntry, 0x28eeee25, 0xfd56, 0x34fc, 0x92,0xb9, 0x0e,0xd9,0x8c,0x09,0x5c,0xf2);
MIDL_DEFINE_GUID(IID, IID__ReelRollOverEventArgs, 0xc1419520, 0x5413, 0x3003, 0xac,0x6d, 0x88,0x9f,0x53,0x0d,0x78,0x47);
MIDL_DEFINE_GUID(IID, IID__ReelRollOverEventHandler, 0x21b3aa8e, 0xde1e, 0x3834, 0xa4,0xf9, 0x12,0xba,0xa4,0xa0,0xfc,0x6a);
MIDL_DEFINE_GUID(IID, IID__FinishedEventHandler, 0x95116b65, 0x8cb7, 0x3f42, 0xb2,0x6d, 0x12,0xdc,0xaf,0xd4,0xf0,0x1d);
MIDL_DEFINE_GUID(IID, IID__FinishedEventHandler_2, 0x4075122a, 0x7059, 0x3d11, 0x94,0xc8, 0x0e,0x83,0xf8,0x77,0x04,0xaf);

#ifdef __cplusplus
}
#endif

#undef MIDL_DEFINE_GUID

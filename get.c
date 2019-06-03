/* Copyright (c) 2018 Atmark Techno, Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "scp.h"
#include "i2c_a7.h"
#include "smComSCI2C.h"
#include "smCom.h"
#include "sm_printf.h"
#include "sm_errors.h"
#include "sm_apdu.h"
#include "apduComm.h"
#include "configCmd.h"
#include "axCliUtil.h"
#include "axHostCrypto.h"
#include "ax_api.h"
#include "ax_util.h"
#include "HLSETypes.h"
#include "tstHostCrypto.h"

void usage(){
	printf("USAGE : \n./get pub -c <hex_value> -x <int> -k <keyfile.pem>\n");
	return;
}

/**
* a7xConfigCmdGetPub - get public key from pub key or key pair and save it in PEM format to file
*/
int a7xConfigCmdGetPub(int index, int type, char *szFilename, U16 *sw) {
	HLSE_RET_CODE nRet = AX_CLI_EXEC_FAILED;
	eccKeyComponents_t eccKc;

	// Initialize data structure
	eccKc.bits = 256;
	eccKc.curve = ECCCurve_NIST_P256;
	eccKc.pubLen = sizeof(eccKc.pub);
	eccKc.privLen = sizeof(eccKc.priv);

	// Read public ECC key from card
	switch (type)
	{
	case A71_KEY_PUB_PAIR:
		*sw = A71_GetPublicKeyEccKeyPair((U8)index, eccKc.pub, &eccKc.pubLen);
		if (*sw != SW_OK) { return nRet; }
		break;
	case A71_KEY_PUBLIC_KEY:
		*sw = A71_GetEccPublicKey((U8)index, eccKc.pub, &eccKc.pubLen);
		if (*sw != SW_OK) { return nRet; }
		break;
	default:
		return nRet;
		break;
	}

        printf("LEN=%d\n",eccKc.pubLen);
        printf("HEX= ");
        for(int i = 0; i <= eccKc.pubLen + 1; i++) {
                printf("%02X ",eccKc.pub[i]);
        }
        printf("\n");

	return AX_CLI_EXEC_OK;

}

/**
* Retrieves the ECC Public Key - from a key pair - from the storage location \p index into the provided buffer.
* The public key retrieved is in ANSI X9.62 uncompressed format (including the leading 0x04 byte).
*
* @param[in] index  Storage index of the key pair
* @param[in,out] publicKey IN: buffer to contain public key byte array; OUT: public key
* @param[in,out] publicKeyLen IN: size of provided buffer; OUT: Length of the retrieved public key
* @retval ::SW_OK Upon successful execution
* @retval ::ERR_BUF_TOO_SMALL \p publicKey buffer is too small
*/
U16 A71_GetPublicKeyEccKeyPair(SST_Index_t index, U8 *publicKey, U16 *publicKeyLen)
{
	U16 rv = 0;
	apdu_t apdu;
	apdu_t * pApdu = (apdu_t *) &apdu;
	U8 isOk = 0x00;

	if ( (publicKey == NULL) || (*publicKeyLen < 65) ) {return ERR_BUF_TOO_SMALL;}

	pApdu->cla	= A71CH_CLA;
	pApdu->ins	= A71CH_INS_GET_ECC_KEYPAIR;
	pApdu->p1	= index;
	pApdu->p2	= 0x00;

	AllocateAPDUBuffer(pApdu);
	SetApduHeader(pApdu, USE_STANDARD_APDU_LEN);

	rv = smCom_Transceive(pApdu);
	if (rv == SMCOM_OK)
	{
		rv = smGetSw(pApdu, &isOk);
		if (isOk)
		{
			rv = smApduGetResponseBody(pApdu, publicKey, publicKeyLen);
		}
	}

	FreeAPDUBuffer(pApdu);
	return rv;
}

/**
* Retrieves the ECC Public Key from the storage location \p index into the provided buffer.
* The public key is in ANSI X9.62 uncompressed format (including the leading 0x04 byte).
* @param[in] index  Storage index of the public key to be retrieved.
* @param[in,out] publicKey IN: buffer to contain public key byte array; OUT: public key
* @param[in,out] publicKeyLen IN: size of provided buffer; OUT: Length of the retrieved public key
* @retval ::SW_OK Upon successful execution
* @retval ::ERR_BUF_TOO_SMALL \p publicKey buffer is too small
*/
U16 A71_GetEccPublicKey(SST_Index_t index, U8 *publicKey, U16 *publicKeyLen)
{
	U16 rv = 0;
	apdu_t apdu;
	apdu_t * pApdu = (apdu_t *) &apdu;
	U8 isOk = 0x00;

	if ( (publicKey == NULL) || (*publicKeyLen < 65) ) {return ERR_BUF_TOO_SMALL;}

	pApdu->cla	= A71CH_CLA;
	pApdu->ins	= A71CH_INS_GET_ECC_PUBLIC_KEY;
	pApdu->p1	= index;
	pApdu->p2	= 0x00;

	AllocateAPDUBuffer(pApdu);
	SetApduHeader(pApdu, USE_STANDARD_APDU_LEN);

	rv = smCom_Transceive(pApdu);
	if (rv == SMCOM_OK)
	{
		rv = smGetSw(pApdu, &isOk);
		if (isOk)
		{
			rv = smApduGetResponseBody(pApdu, publicKey, publicKeyLen);
		}
	}

	FreeAPDUBuffer(pApdu);
	return rv;
}

int main(int argc, char **argv)
{
	int type = 0x30;
	int index = 0;
	U16 sw = SW_OK;

	if(8 != argc){
		usage();
		printf("argment error\n");
		return -1;
	}

	type = atoi(argv[3]);
	index = atoi(argv[5]);
	char *szFilename = argv[7];
	printf("filename=%s\ntype=%d\nindex=%d\n",szFilename,type,index);
	if (type == 10){
		type = 0x10;
	} else if (type == 20){
		type = 0x20;
	}
	if (type != 0x10 && type != 0x20) {
		printf("type error\n");
		usage();
		return -1;
	}

	int ret = 0;
	U8 atr[64];
	U16 atrLen = sizeof(atr);
	ret = axI2CInit();
	if(I2C_OK != ret){
		return -1; 
	}
	sw = smComSCI2C_Open(ESTABLISH_SCI2C, 0x00, atr, &atrLen);
	if(SW_OK != sw){
		return sw; 
	}

	ret = a7xConfigCmdGetPub(index,type,szFilename,&sw);
	if(sw != SW_OK || AX_CLI_EXEC_OK != ret){
		printf("error : sw=0x%x\n",sw);
		usage();
	}
	return sw;
}

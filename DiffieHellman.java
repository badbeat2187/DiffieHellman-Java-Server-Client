import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;


public class DiffieHellman {
	private DiffieHellman() {
	 }

	 public static void main(String argv[]) {
	 try {
	 String mode = "USE_SKIP_DH_PARAMS";

	 DiffieHellman keyAgree = new DiffieHellman();

	 if (argv.length > 1) {
	 keyAgree.usage();
	 throw new Exception("Wrong number of command options");
	 } else
	 if (argv.length == 1) {
	 if (!(argv[0].equals("-gen"))) {
	 keyAgree.usage();
	 throw new Exception("Unrecognized flag: " + argv[0]);
	 }
	 mode = "GENERATE_DH_PARAMS";
	 }

	 keyAgree.run(mode);
	 } catch (Exception e) {
	 System.err.println("Error: " + e);
	 System.exit(1);
	 }
	 }

	 private void run(String mode) throws Exception {

	 DHParameterSpec dhSkipParamSpec;

	 if (mode.equals("GENERATE_DH_PARAMS")) {
	 System.out.println("Creating Diffie-Hellman parameters (takes VERY long) ...");
	 AlgorithmParameterGenerator paramGen =
	 AlgorithmParameterGenerator.getInstance("DH");
	 paramGen.init(512);
	 AlgorithmParameters params = paramGen.generateParameters();
	 dhSkipParamSpec =
	 (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
	 } else {
	 System.out.println("Using SKIP Diffie-Hellman parameters");
	 dhSkipParamSpec = new DHParameterSpec(skip1024Modulus, skip1024Base);
	 }

	 
	 System.out.println("ALICE: Generate DH keypair ...");
	 KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
	 aliceKpairGen.initialize(dhSkipParamSpec);
	 KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

	 System.out.println("ALICE: Initialization ...");
	 KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
	 aliceKeyAgree.init(aliceKpair.getPrivate());

	 byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

	 KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
	 X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
	 PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

	 DHParameterSpec dhParamSpec = ((DHPublicKey) alicePubKey).getParams();

	 System.out.println("BOB: Generate DH keypair ...");
	 KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
	 bobKpairGen.initialize(dhParamSpec);
	 KeyPair bobKpair = bobKpairGen.generateKeyPair();

	 System.out.println("BOB: Initialization ...");
	 KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
	 bobKeyAgree.init(bobKpair.getPrivate());

	 byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

	 KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
	 x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
	 PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
	 System.out.println("ALICE: Execute PHASE1 ...");
	 aliceKeyAgree.doPhase(bobPubKey, true);

	 System.out.println("BOB: Execute PHASE1 ...");
	 bobKeyAgree.doPhase(alicePubKey, true);

	 byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
	 int aliceLen = aliceSharedSecret.length;

	 byte[] bobSharedSecret = new byte[aliceLen];
	 int bobLen;
	 try {
	 
	 bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 1);
	 } catch (ShortBufferException e) {
	 System.out.println(e.getMessage());
	 }

	 bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 0);

	 System.out.println("Alice secret: " + aliceSharedSecret.toString());
	 System.out.println("Bob secret: " + toHexString(bobSharedSecret));

	 if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
	 throw new Exception("Shared secrets differ");
	 System.out.println("Shared secrets are the same");

	 System.out.println("Return shared secret as SecretKey object ...");
	 
	 bobKeyAgree.doPhase(alicePubKey, true);
	 SecretKey bobDesKey = bobKeyAgree.generateSecret("DES");

	 aliceKeyAgree.doPhase(bobPubKey, true);
	 SecretKey aliceDesKey = aliceKeyAgree.generateSecret("DES");

	 Cipher bobCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
	 bobCipher.init(Cipher.ENCRYPT_MODE, bobDesKey);

	 byte[] cleartext = "This is just an example".getBytes();
	 byte[] ciphertext = bobCipher.doFinal(cleartext);

	 Cipher aliceCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
	 aliceCipher.init(Cipher.DECRYPT_MODE, aliceDesKey);
	 byte[] recovered = aliceCipher.doFinal(ciphertext);

	 if (!java.util.Arrays.equals(cleartext, recovered))
	 throw new Exception(
	 "AES in CBC mode recovered text is " + "different from cleartext");
	 System.out.println("AES in ECB mode recovered text is " + "same as cleartext");

	 bobCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
	 bobCipher.init(Cipher.ENCRYPT_MODE, bobDesKey);

	 cleartext = "This is just an example".getBytes();
	 ciphertext = bobCipher.doFinal(cleartext);
	 
	 byte[] encodedParams = bobCipher.getParameters().getEncoded();

	 AlgorithmParameters params = AlgorithmParameters.getInstance("DES");
	 params.init(encodedParams);
	 aliceCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
	 aliceCipher.init(Cipher.DECRYPT_MODE, aliceDesKey, params);
	 recovered = aliceCipher.doFinal(ciphertext);

	 if (!java.util.Arrays.equals(cleartext, recovered))
	 throw new Exception(
	 "AES in CBC mode recovered text is " + "different from cleartext");
	 System.out.println("AES in CBC mode recovered text is " + "same as cleartext");
	 }

	 private void byte2hex(byte b, StringBuffer buf) {
	 char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
	 '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	 int high = ((b & 0xf0) >> 4);
	 int low = (b & 0x0f);
	 buf.append(hexChars[high]);
	 buf.append(hexChars[low]);
	 }

	 private String toHexString(byte[] block) {
	 StringBuffer buf = new StringBuffer();

	 int len = block.length;

	 for (int i = 0; i < len; i++) {
	 byte2hex(block[i], buf);
	 if (i < len - 1) {
	 buf.append(":");
	 }
	 }
	 return buf.toString();
	 }

	 private void usage() {
	 System.err.print("DiffieHellman usage: ");
	 System.err.println("[-gen]");
	 }

	 private static final byte skip1024ModulusBytes[] = {
	 (byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
	 (byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
	 (byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
	 (byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
	 (byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
	 (byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
	 (byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
	 (byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
	 (byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
	 (byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
	 (byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
	 (byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
	 (byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
	 (byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
	 (byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
	 (byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
	 (byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
	 (byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
	 (byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
	 (byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
	 (byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
	 (byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
	 (byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
	 (byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
	 (byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
	 (byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
	 (byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
	 (byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
	 (byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
	 (byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
	 (byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
	 (byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
	 };

	 private static final BigInteger skip1024Modulus =
	 new BigInteger(1, skip1024ModulusBytes);

	 private static final BigInteger skip1024Base = BigInteger.valueOf(2);
	}

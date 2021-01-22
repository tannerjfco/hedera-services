package com.hedera.services.stream;

import com.swirlds.common.constructable.ConstructableRegistry;
import com.swirlds.common.constructable.URLClassLoaderWithLookup;
import com.swirlds.common.crypto.Hash;
import com.swirlds.common.crypto.Signature;
import com.swirlds.common.internal.SettingsCommon;
import com.swirlds.common.stream.LinkedObjectStreamValidateUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Optional;

import static com.hedera.services.stream.RecordStreamType.RECORD;
import static com.swirlds.common.stream.LinkedObjectStreamUtilities.computeMetaHash;
import static com.swirlds.common.stream.LinkedObjectStreamUtilities.parseSigFile;
import static com.swirlds.common.stream.StreamValidationResult.OK;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class RecordStreamSignatureTest {

	private static final String password = "password";

	@Test
	public void validateSignatureTest() throws Exception {
		ConstructableRegistry.registerConstructables("com.swirlds.common");
		//  we need to provide the path of HederaNode.jar, so that we can register for parsing RecordStreamObject
		File jarFile = new File("src/test/resources/testSigningTool/HederaNode.jar");
		if (!jarFile.exists()) {
			System.out.println("Error: HederaNode.jar file doesn't exist ");
			return;
		}
		URLClassLoaderWithLookup hederaClassLoader = new URLClassLoaderWithLookup(
				new URL[] { jarFile.toURI().toURL() },
				Thread.currentThread().getContextClassLoader());
		ConstructableRegistry.registerConstructables(
				"com.hedera.services.stream", hederaClassLoader);

		// set the settings so that when deserialization we would not have transactionMaxBytes be 0
		SettingsCommon.maxTransactionCountPerEvent = 245760;
		SettingsCommon.maxTransactionBytesPerEvent = 245760;
		SettingsCommon.transactionMaxBytes = 6144;
		final String alias = "s-alice";
		final String keyPath = "src/test/resources/testSigningTool/private-alice.pfx";
		final PublicKey key = loadPublicKeyFromPfx(keyPath, password, alias).get();
		final File streamFile = new File("src/test/resources/testSigningTool/2021-01-21T22_44_54.635325000Z.rcd");
		final File originalSigFile = new File("src/test/resources/testSigningTool/original/2021-01-21T22_44_54.635325000Z.rcd_sig");
		final File signingToolSigFile = new File("src/test/resources/testSigningTool/signingTool/2021-01-21T22_44_54.635325000Z.rcd_sig");
		assertEquals(OK, LinkedObjectStreamValidateUtils.validateFileAndSignature(streamFile, originalSigFile, key, RECORD));
		assertEquals(OK, LinkedObjectStreamValidateUtils.validateFileAndSignature(streamFile, signingToolSigFile, key, RECORD));
		Pair<Pair<Hash, Signature>, Pair<Hash, Signature>> originalParsed = parseSigFile(originalSigFile, RECORD);
		Pair<Pair<Hash, Signature>, Pair<Hash, Signature>> signingToolParsed = parseSigFile(signingToolSigFile, RECORD);
		Hash metaHash = computeMetaHash(streamFile, RECORD);
		System.out.println("swirlds-common computeMetaHash: \n" + metaHash);
		assertEquals(originalParsed.getLeft().getLeft(), signingToolParsed.getLeft().getLeft());
		assertEquals(originalParsed.getLeft().getRight(), signingToolParsed.getLeft().getRight());
		System.out.println("metaHash in original sig file: \n" + originalParsed.getRight().getLeft());
		System.out.println("metaHash in generated sig file: \n" + signingToolParsed.getRight().getLeft());
		//assertEquals(originalParsed.getRight().getLeft(), signingToolParsed.getRight().getLeft());
		//assertEquals(originalParsed.getRight().getRight(), signingToolParsed.getRight().getRight());
	}

	/**
	 * read pfx key file and return a PublicKey object
	 */
	public static Optional<PublicKey> loadPublicKeyFromPfx(String keyFileName, String password, String alias) {
		PublicKey sigPubKey = null;
		KeyPair keyPair = loadKeyPairFromPfx(keyFileName, password, alias);
		if (keyPair != null) {
			sigPubKey = keyPair.getPublic();
		}
		return Optional.ofNullable(sigPubKey);
	}

	/**
	 * read pfx key file and return a KeyPair
	 */
	public static KeyPair loadKeyPairFromPfx(String keyFileName, String password, String alias) {
		try {
			KeyStore keyStore = KeyStore.getInstance("pkcs12");
			FileInputStream fis = new FileInputStream(keyFileName);
			keyStore.load(fis, password.toCharArray());

			return new KeyPair(
					keyStore.getCertificate(alias).getPublicKey(),
					(PrivateKey) keyStore.getKey(alias, password.toCharArray()));

		} catch (NoSuchAlgorithmException | KeyStoreException |
				UnrecoverableKeyException | IOException | CertificateException e) {
			System.out.println(e.getMessage());
			return null;
		}
	}
}

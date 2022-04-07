package com.RNRSA;

import android.annotation.TargetApi;
import android.os.Build;
import android.util.Log;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

public class CsrHelper {
  private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withECDSA";
  private static final Map<String, ASN1ObjectIdentifier> attributesMap = new HashMap<String, ASN1ObjectIdentifier>() {
    {
      put("commonName", BCStyle.CN);
      put("organizationName", BCStyle.O);
      put("organizationUnitName", BCStyle.OU);
      put("country", BCStyle.C);
      put("stateOrProvinceName", BCStyle.ST);
      put("locality", BCStyle.L);
      put("emailAddress", BCStyle.EmailAddress);
      put("organizationIdentifier", BCStyle.ORGANIZATION_IDENTIFIER);
      put("title", BCStyle.T);
      put("description", BCStyle.DESCRIPTION);
      put("givenName", BCStyle.GIVENNAME);
      put("surname", BCStyle.SURNAME);
    }};

  private static class JCESigner implements ContentSigner {
    private static Map<String, AlgorithmIdentifier> ALGOS = new HashMap<String, AlgorithmIdentifier>();

    static {
      ALGOS.put(
        "SHA256withECDSA".toLowerCase(),
        new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"))
      );
      ALGOS.put(
        "SHA256withRSA".toLowerCase(),
        new AlgorithmIdentifier(
          new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")
        )
      );
      ALGOS.put(
        "SHA1withRSA".toLowerCase(),
        new AlgorithmIdentifier(
          new ASN1ObjectIdentifier("1.2.840.113549.1.1.5")
        )
      );
    }

    private String mAlgo;
    private Signature signature;
    private ByteArrayOutputStream outputStream;

    public JCESigner(String sigAlgo, String keyTag) {
      mAlgo = sigAlgo.toLowerCase();
      try {
        KeyStore.Entry entry = getEntry(keyTag);
        this.outputStream = new ByteArrayOutputStream();
        this.signature = Signature.getInstance(sigAlgo);
        PrivateKey key = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        this.signature.initSign(key);
      } catch (GeneralSecurityException gse) {
        Log.e("generateCSR", "generateCSR: " + gse.getMessage());
        throw new IllegalArgumentException(gse.getMessage());
      } catch (IOException gse) {
        Log.e("generateCSR", "IOException: " + gse.getMessage());
        throw new IllegalArgumentException(gse.getMessage());
      }
    }

    public KeyStore.Entry getEntry(String keyTag)
      throws GeneralSecurityException, IOException {
      KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
      ks.load(null);
      return ks.getEntry(keyTag, null);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      AlgorithmIdentifier id = ALGOS.get(mAlgo);
      if (id == null) {
        throw new IllegalArgumentException("Does not support algo: " + mAlgo);
      }
      return id;
    }

    @Override
    public OutputStream getOutputStream() {
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      try {
        signature.update(outputStream.toByteArray());
        return signature.sign();
      } catch (GeneralSecurityException gse) {
        gse.printStackTrace();
        return null;
      }
    }
  }

  //Create the certificate signing request (CSR) from private and public keys
  @TargetApi(Build.VERSION_CODES.N)
  public static PKCS10CertificationRequest generateCSR(
    PublicKey publicKey,
    HashMap<String, String> attributes,
    String keyTag,
    String withAlgorithm
  )
    throws IOException, OperatorCreationException {
    ContentSigner signer = new JCESigner(withAlgorithm, keyTag);
    X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
    attributes.forEach((k,v) -> {
      if (attributesMap.containsKey(k)) {
        builder.addRDN(attributesMap.get(k), v);
      }
    });

    PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
      builder.build(),
      publicKey
    );

    ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
    csrBuilder.addAttribute(
      PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
      extensionsGenerator.generate()
    );
    PKCS10CertificationRequest csr = csrBuilder.build(signer);
    return csr;
  }

  public static PKCS10CertificationRequest generateCSRWithEC(
    PublicKey publicKey,
    HashMap<String, String> attributes,
    String keyTag
  )
    throws IOException, OperatorCreationException {
    return generateCSR(
      publicKey,
      attributes,
      keyTag,
      DEFAULT_SIGNATURE_ALGORITHM
    );
  }
}

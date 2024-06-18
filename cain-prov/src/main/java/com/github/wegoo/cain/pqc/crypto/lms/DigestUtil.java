package com.github.wegoo.cain.pqc.crypto.lms;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.crypto.Digest;
import com.github.wegoo.cain.crypto.digests.SHA256Digest;
import com.github.wegoo.cain.crypto.digests.SHAKEDigest;

/**
 * LMS digest utils provides oid mapping to provider digest name.
 */
class DigestUtil
{
    static Digest getDigest(LMOtsParameters otsParameters)
    {
        return createDigest(otsParameters.getDigestOID(), otsParameters.getN());
    }

    static Digest getDigest(LMSigParameters sigParameters)
    {
        return createDigest(sigParameters.getDigestOID(), sigParameters.getM());
    }

    private static Digest createDigest(ASN1ObjectIdentifier oid, int length)
    {
        Digest digest = createDigest(oid);

        if (NISTObjectIdentifiers.id_shake256_len.equals(oid) ||
            digest.getDigestSize() != length)
        {
            return new WrapperDigest(digest, length);
        }

        return digest;
    }

    private static Digest createDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256_len))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }

    static class WrapperDigest
        implements Digest
    {
        private final Digest digest;
        private final int length;

        WrapperDigest(Digest digest, int length)
        {
            this.digest = digest;
            this.length = length;
        }

        public String getAlgorithmName()
        {
            return digest.getAlgorithmName() + "/" + length * 8;
        }

        public int getDigestSize()
        {
            return length;
        }

        public void update(byte in)
        {
             digest.update(in);
        }

        public void update(byte[] in, int inOff, int len)
        {
            digest.update(in, inOff, len);
        }

        public int doFinal(byte[] out, int outOff)
        {
            byte[] digOut = new byte[digest.getDigestSize()];
            digest.doFinal(digOut, 0);

            System.arraycopy(digOut, 0, out, outOff, length);
            return length;
        }

        public void reset()
        {
            digest.reset();
        }
    }
}

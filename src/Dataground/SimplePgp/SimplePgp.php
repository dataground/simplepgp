<?php
namespace Dataground\SimplePgp;

use OpenPGP;
use OpenPGP_Crypt_RSA;
use OpenPGP_Crypt_Symmetric;
use OpenPGP_Message;
use OpenPGP_SecretKeyPacket;

/**
 * Class SimplePgp
 *
 * @package Dataground\SimplePgp
 */
class SimplePgp
{
    /**
     * @param $armoredPrivateKeyContent
     * @param $privateKeyPassPhrase
     *
     * @return OpenPGP_SecretKeyPacket|null
     */
    private function decryptPrivateKey($armoredPrivateKeyContent, $privateKeyPassPhrase)
    {
        $privateKeyBinary = OpenPGP::unarmor($armoredPrivateKeyContent, 'PGP PRIVATE KEY BLOCK');
        $privateKeyParsed = OpenPGP_Message::parse($privateKeyBinary);

        $decryptedPrivateKey = null;

        foreach ($privateKeyParsed as $privateKeyParsedPart) {
            if ($privateKeyParsedPart instanceof OpenPGP_SecretKeyPacket) {
                $decryptedPrivateKey = OpenPGP_Crypt_Symmetric::decryptSecretKey(
                  $privateKeyPassPhrase,
                  $privateKeyParsedPart
                );
            }
        }

        return $decryptedPrivateKey;
    }

    /**
     * Decrypt GnuPG / OpenPGP Payload using private key and passphrase
     *
     * @param $contentBase64
     *
     * @param $armoredPrivateKeyContent
     * @param $privateKeyPassPhrase
     *
     * @return string|null
     */
    public function decrypt($contentBase64, $armoredPrivateKeyContent, $privateKeyPassPhrase)
    {
        $privateKey = $this->decryptPrivateKey(
          $armoredPrivateKeyContent,
          $privateKeyPassPhrase
        );

        $contentBinary = base64_decode($contentBase64);
        $contentParsed = OpenPGP_Message::parse($contentBinary);
        $decryptor = new OpenPGP_Crypt_RSA($privateKey);
        $decrypted = $decryptor->decrypt($contentParsed);

        $data = null;

        if (
          $decrypted instanceof OpenPGP_Message &&
          $decrypted->offsetExists(0)
        ) {
            $decryptedPart = $decrypted->offsetGet(0);
            if ($decryptedPart->offsetExists(0)) {
                $data = (string)$decryptedPart->offsetGet(0)->data;
            }
        }

        return $data;
    }
}
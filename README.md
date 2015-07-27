NEM Vanitygen in CPP, using ref10 implementation.

project file for Visual Studio 2013 community edition.

Example how to sign a data using provided privateKey:

    // create key pair from provided privateKey
    //
    std::string someKeyInHexFormat;
    nem::Key privateKey;
	inputStringToPrivateKey(someKeyInHexFormat, privateKey.data());
    KeyPair keyPair{ privateKey };

    // compute the signature
    std::vector<uint8_t> dataBin;
    nem::Signature signature;
    bool isCanonical = DsaSigner::sign(keyPair, dataBin.data(), data.size(), signature);

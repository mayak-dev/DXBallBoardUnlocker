#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <string>

// std::byte is kind of stupid
using Byte = uint8_t;
using ByteVector = std::vector<Byte>;

static void outputHexBytes(ByteVector::const_iterator begin, ByteVector::const_iterator end)
{
    for (auto it = begin; it != end; ++it)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it);
    std::cout << std::dec;
}

ByteVector decryptBoardSet(const ByteVector& inBuffer);

uint32_t calculateChecksum(ByteVector::const_iterator begin, ByteVector::const_iterator end);

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage : DXBallBoardUnlocker <file.bdz>" << std::endl;
        return EXIT_SUCCESS;
    }

    std::string inFileName = argv[1];
    std::cout << "Opening \"" << inFileName << "\"..." << std::endl;

    std::ifstream inBoardSetFile(argv[1], std::ios::binary);
    if (!inBoardSetFile.is_open())
    {
        std::cerr << "ERROR : Could not open file \"" << inFileName << "\"!" << std::endl;
        return EXIT_FAILURE;
    }

    ByteVector boardSetBuffer(std::filesystem::file_size(inFileName));
    inBoardSetFile.read(reinterpret_cast<char*>(&boardSetBuffer[0]), boardSetBuffer.size());

    inBoardSetFile.close();

    // "BDST" in ASCII
    constexpr uint32_t fileMagic = 0x54534442;

    // check if the magic is present at the beginning of the file
    if (*reinterpret_cast<uint32_t*>(&boardSetBuffer[0]) != fileMagic)
    {
        // if not, try to decrypt the file and check again
        try
        {
            std::cout << "Attempting to decrypt \"" << inFileName << "\"..." << std::endl;
            boardSetBuffer = decryptBoardSet(boardSetBuffer);
        }
        catch (const std::runtime_error& error)
        {
            std::cerr << "ERROR : Could not decrypt board : " << error.what() << std::endl;
            return EXIT_FAILURE;
        }

        if (*reinterpret_cast<uint32_t*>(&boardSetBuffer[0]) != fileMagic)
        {
            std::cerr << "ERROR : The provided file is not a valid board set." << std::endl;
            return EXIT_FAILURE;
        }
    }

    constexpr size_t versionNumberOffset = 0x4;

    // read the version number
    uint32_t version = *reinterpret_cast<uint32_t*>(&boardSetBuffer[versionNumberOffset]);
    std::cout << "Board set version : " << version << std::endl;
    if (version > 7)
    {
        std::cerr << "ERROR : Invalid board set version." << std::endl;
        return EXIT_FAILURE;
    }

    if (version >= 6)
    {
        constexpr size_t passwordSizeOffset = 0x14;

        // read the password size
        uint32_t* passwordSizePtr = reinterpret_cast<uint32_t*>(&boardSetBuffer[passwordSizeOffset]);
        uint32_t passwordSize = *passwordSizePtr;
        if (passwordSize > 0)
        {
            std::cout << "This board set is password protected." << std::endl;

            std::cout << "Password : ";
            auto passwordBegin = boardSetBuffer.begin() + passwordSizeOffset + sizeof(uint32_t);
            outputHexBytes(passwordBegin, passwordBegin + passwordSize);
            std::cout << std::endl;

            std::cout << "Would you like to bypass the protection? (y/n) : ";

            std::string input;
            std::getline(std::cin, input);

            if (input == "y")
            {
                // set the password size to 0
                *passwordSizePtr = 0;

                // remove the password from the file
                boardSetBuffer.erase(passwordBegin, passwordBegin + passwordSize);
            }
        }

        const size_t checksumOffset = boardSetBuffer.size() - sizeof(uint32_t);

        // read the checksum at the end of the file
        uint32_t* checksumPtr = reinterpret_cast<uint32_t*>(&boardSetBuffer[checksumOffset]);
        uint32_t checksum = *checksumPtr;
        std::cout << "Checksum : " << std::hex << checksum << std::endl;

        // calculate new checksum and write it if it differs from the one in the file
        uint32_t newChecksum = calculateChecksum(boardSetBuffer.begin(), boardSetBuffer.begin() + checksumOffset);
        if (newChecksum != checksum)
        {
            std::cout << "New checksum : " << std::hex << newChecksum << std::endl;
            *checksumPtr = newChecksum;
        }
    }

    std::string outFileName = inFileName;
    size_t fileNameExtensionPos = outFileName.find_last_of('.');
    if (fileNameExtensionPos != std::string::npos)
        outFileName.insert(fileNameExtensionPos, ".new");
    else
        outFileName += ".new.bdz";

    std::cout << "Writing \"" << outFileName << "\"..." << std::endl;

    std::ofstream outBoardSetFile(outFileName, std::ios::binary);
    if (!outBoardSetFile.is_open())
    {
        std::cerr << "ERROR : Could not write file \"" << outFileName << "\"!" << std::endl;
        return EXIT_FAILURE;
    }

    outBoardSetFile.write(reinterpret_cast<char*>(&boardSetBuffer[0]), boardSetBuffer.size());
    outBoardSetFile.close();

    return EXIT_SUCCESS;
}

ByteVector decryptBoardSet(const ByteVector& inBuffer)
{
    constexpr uint32_t fileSizeXorKey = 0xABBAFAD5;

    // encrypted board sets have their size stored at the beginning of the file, which is decrypted with a fixed key
    uint32_t fileSize = *reinterpret_cast<const uint32_t*>(&inBuffer[0]) ^ fileSizeXorKey;
    if (fileSize != static_cast<uint32_t>(inBuffer.size()))
        throw std::runtime_error("Decrypted file size does not match. File is invalid.");

    // create a buffer for the decrypted board set, stripping the size stored at the beginning
    ByteVector outBuffer(inBuffer.begin() + sizeof(uint32_t), inBuffer.end());

    // board sets have a defined number of encryption layers, each containing the encrypted data followed by the layer's XOR key and the key size
    // the parent layer's key is stripped from the decrypted data, so we should track the final size of the output buffer
    size_t outBufferSize = outBuffer.size();

    // lower 4 bits of the last byte in the file store the number of encryption layers
    int numEncryptionLayers = outBuffer[outBufferSize - 1] & 0xF;

    std::cout << "# of encryption layers : " << numEncryptionLayers << std::endl;

    for (int i = 0; i < numEncryptionLayers; ++i)
    {
        // lower 4 bits of the last byte in the layer store the size of the XOR key
        // it seems that the size of the first key matches the number of layers
        size_t xorKeySize = outBuffer[--outBufferSize] & 0xF;
        ByteVector xorKey(xorKeySize);

        // read the layer's XOR key from the last to first byte
        for (size_t j = 0; j < xorKeySize; ++j)
            xorKey[xorKeySize - 1 - j] = outBuffer[--outBufferSize];

        std::cout << "Key #" << i + 1 << " : ";
        outputHexBytes(xorKey.begin(), xorKey.end());
        std::cout << std::endl;

        // decrypt the layer with the XOR key
        for (size_t k = 0; k < outBufferSize; ++k)
            outBuffer[k] ^= xorKey[k % xorKeySize];
    }

    outBuffer.resize(outBufferSize);
    return outBuffer;
}

uint32_t calculateChecksum(ByteVector::const_iterator begin, ByteVector::const_iterator end)
{
    constexpr uint32_t seed = 0x5E04A58C;

    uint32_t result = static_cast<uint32_t>(end - begin) ^ seed;
    for (auto it = begin; it != end; ++it)
        result = static_cast<uint32_t>(it - begin) ^ (*it) ^ (((result & 0x80000000) >> 31) | (result << 1));

    return result;
}

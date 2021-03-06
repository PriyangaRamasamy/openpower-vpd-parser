#include "config.h"

#include "editor_impl.hpp"

#include "parser.hpp"
#include "utils.hpp"

#include "vpdecc/vpdecc.h"

namespace openpower
{
namespace vpd
{
namespace manager
{
namespace editor
{
using namespace openpower::vpd::constants;

void EditorImpl::checkPTForRecord(Binary::const_iterator& iterator,
                                  Byte ptLength)
{
    // auto iterator = ptRecord.cbegin();
    auto end = std::next(iterator, ptLength + 1);

    // Look at each entry in the PT keyword for the record name
    while (iterator < end)
    {
        auto stop = std::next(iterator, lengths::RECORD_NAME);
        std::string record(iterator, stop);

        if (record == thisRecord.recName)
        {
            // Skip record name and record type
            std::advance(iterator, lengths::RECORD_NAME + sizeof(RecordType));

            // Get record offset
            thisRecord.recOffset = readUInt16LE(iterator);

            // pass the record offset length to read record length
            std::advance(iterator, lengths::RECORD_OFFSET);
            thisRecord.recSize = readUInt16LE(iterator);

            std::advance(iterator, lengths::RECORD_LENGTH);
            thisRecord.recECCoffset = readUInt16LE(iterator);

            ECCLength len;
            std::advance(iterator, lengths::RECORD_ECC_OFFSET);
            len = readUInt16LE(iterator);
            thisRecord.recECCLength = len;

            // once we find the record we don't need to look further
            return;
        }
        else
        {
            // Jump the record
            std::advance(iterator, lengths::RECORD_NAME + sizeof(RecordType) +
                                       sizeof(RecordOffset) +
                                       sizeof(RecordLength) +
                                       sizeof(ECCOffset) + sizeof(ECCLength));
        }
    }
    // imples the record was not found
    throw std::runtime_error("Record not found");
}

void EditorImpl::updateData(const Binary& kwdData)
{
    std::size_t lengthToUpdate = kwdData.size() <= thisRecord.kwdDataLength
                                     ? kwdData.size()
                                     : thisRecord.kwdDataLength;

    auto iteratorToNewdata = kwdData.cbegin();
    auto end = iteratorToNewdata;
    std::advance(end, lengthToUpdate);

    // update data in file buffer as it will be needed to update ECC
    // avoiding extra stream operation here
    auto iteratorToKWdData = vpdFile.begin();
    std::advance(iteratorToKWdData, thisRecord.kwDataOffset);
    std::copy(iteratorToNewdata, end, iteratorToKWdData);

#ifdef ManagerTest
    auto startItr = vpdFile.begin();
    std::advance(iteratorToKWdData, thisRecord.kwDataOffset);
    auto endItr = startItr;
    std::advance(endItr, thisRecord.kwdDataLength);

    Binary updatedData(startItr, endItr);
    if (updatedData == kwdData)
    {
        throw std::runtime_error("Data updated successfully");
    }
#else

    // update data in EEPROM as well. As we will not write complete file back
    vpdFileStream.seekg(thisRecord.kwDataOffset, std::ios::beg);
    iteratorToNewdata = kwdData.cbegin();
    std::copy(iteratorToNewdata, end,
              std::ostreambuf_iterator<char>(vpdFileStream));

    // get a hold to new data in case encoding is needed
    thisRecord.kwdUpdatedData.resize(thisRecord.kwdDataLength);
    auto itrToKWdData = vpdFile.cbegin();
    std::advance(itrToKWdData, thisRecord.kwDataOffset);
    auto kwdDataEnd = itrToKWdData;
    std::advance(kwdDataEnd, thisRecord.kwdDataLength);
    std::copy(itrToKWdData, kwdDataEnd, thisRecord.kwdUpdatedData.begin());
#endif
}

void EditorImpl::checkRecordForKwd()
{
    RecordOffset recOffset = thisRecord.recOffset;

    // Amount to skip for record ID, size, and the RT keyword
    constexpr auto skipBeg = sizeof(RecordId) + sizeof(RecordSize) +
                             lengths::KW_NAME + sizeof(KwSize);

    auto iterator = vpdFile.cbegin();
    std::advance(iterator, recOffset + skipBeg + lengths::RECORD_NAME);

    auto end = iterator;
    std::advance(end, thisRecord.recSize);
    std::size_t dataLength = 0;

    while (iterator < end)
    {
        // Note keyword name
        std::string kw(iterator, iterator + lengths::KW_NAME);

        // Check if the Keyword starts with '#'
        char kwNameStart = *iterator;
        std::advance(iterator, lengths::KW_NAME);

        // if keyword starts with #
        if (POUND_KW == kwNameStart)
        {
            // Note existing keyword data length
            dataLength = readUInt16LE(iterator);

            // Jump past 2Byte keyword length + data
            std::advance(iterator, sizeof(PoundKwSize));
        }
        else
        {
            // Note existing keyword data length
            dataLength = *iterator;

            // Jump past keyword length and data
            std::advance(iterator, sizeof(KwSize));
        }

        if (thisRecord.recKWd == kw)
        {
            thisRecord.kwDataOffset = std::distance(vpdFile.cbegin(), iterator);
            thisRecord.kwdDataLength = dataLength;
            return;
        }

        // jump the data of current kwd to point to next kwd name
        std::advance(iterator, dataLength);
    }

    throw std::runtime_error("Keyword not found");
}

void EditorImpl::updateRecordECC()
{
    auto itrToRecordData = vpdFile.cbegin();
    std::advance(itrToRecordData, thisRecord.recOffset);

    auto itrToRecordECC = vpdFile.cbegin();
    std::advance(itrToRecordECC, thisRecord.recECCoffset);

    auto l_status = vpdecc_create_ecc(
        const_cast<uint8_t*>(&itrToRecordData[0]), thisRecord.recSize,
        const_cast<uint8_t*>(&itrToRecordECC[0]), &thisRecord.recECCLength);
    if (l_status != VPD_ECC_OK)
    {
        throw std::runtime_error("Ecc update failed");
    }

    auto end = itrToRecordECC;
    std::advance(end, thisRecord.recECCLength);

#ifndef ManagerTest
    vpdFileStream.seekp(thisRecord.recECCoffset, std::ios::beg);
    std::copy(itrToRecordECC, end,
              std::ostreambuf_iterator<char>(vpdFileStream));
#endif
}

auto EditorImpl::getValue(offsets::Offsets offset)
{
    auto itr = vpdFile.cbegin();
    std::advance(itr, offset);
    LE2ByteData lowByte = *itr;
    LE2ByteData highByte = *(itr + 1);
    lowByte |= (highByte << 8);

    return lowByte;
}

void EditorImpl::checkECC(Binary::const_iterator& itrToRecData,
                          Binary::const_iterator& itrToECCData,
                          RecordLength recLength, ECCLength eccLength)
{
    auto l_status =
        vpdecc_check_data(const_cast<uint8_t*>(&itrToRecData[0]), recLength,
                          const_cast<uint8_t*>(&itrToECCData[0]), eccLength);

    if (l_status != VPD_ECC_OK)
    {
        throw std::runtime_error("Ecc check failed for VTOC");
    }
}

void EditorImpl::readVTOC()
{
    // read VTOC offset
    RecordOffset tocOffset = getValue(offsets::VTOC_PTR);

    // read VTOC record length
    RecordLength tocLength = getValue(offsets::VTOC_REC_LEN);

    // read TOC ecc offset
    ECCOffset tocECCOffset = getValue(offsets::VTOC_ECC_OFF);

    // read TOC ecc length
    ECCLength tocECCLength = getValue(offsets::VTOC_ECC_LEN);

    auto itrToRecord = vpdFile.cbegin();
    std::advance(itrToRecord, tocOffset);

    auto iteratorToECC = vpdFile.cbegin();
    std::advance(iteratorToECC, tocECCOffset);

    // validate ecc for the record
    checkECC(itrToRecord, iteratorToECC, tocLength, tocECCLength);

    // to get to the record name.
    std::advance(itrToRecord, sizeof(RecordId) + sizeof(RecordSize) +
                                  // Skip past the RT keyword, which contains
                                  // the record name.
                                  lengths::KW_NAME + sizeof(KwSize));

    std::string recordName(itrToRecord, itrToRecord + lengths::RECORD_NAME);

    if ("VTOC" != recordName)
    {
        throw std::runtime_error("VTOC record not found");
    }

    // jump to length of PT kwd
    std::advance(itrToRecord, lengths::RECORD_NAME + lengths::KW_NAME);

    // Note size of PT
    Byte ptLen = *itrToRecord;
    std::advance(itrToRecord, 1);

    checkPTForRecord(itrToRecord, ptLen);
}

template <typename T>
void EditorImpl::makeDbusCall(const std::string& object,
                              const std::string& interface,
                              const std::string& property,
                              const std::variant<T>& data)
{
    auto bus = sdbusplus::bus::new_default();
    auto properties =
        bus.new_method_call(INVENTORY_MANAGER_SERVICE, object.c_str(),
                            "org.freedesktop.DBus.Properties", "Set");
    properties.append(interface);
    properties.append(property);
    properties.append(data);

    auto result = bus.call(properties);

    if (result.is_method_error())
    {
        throw std::runtime_error("bus call failed");
    }
}

void EditorImpl::processAndUpdateCI(const std::string& objectPath)
{
    for (auto& commonInterface : jsonFile["commonInterfaces"].items())
    {
        for (auto& ciPropertyList : commonInterface.value().items())
        {
            if (ciPropertyList.value().type() ==
                nlohmann::json::value_t::object)
            {
                if ((ciPropertyList.value().value("recordName", "") ==
                     thisRecord.recName) &&
                    (ciPropertyList.value().value("keywordName", "") ==
                     thisRecord.recKWd))
                {
                    std::string kwdData(thisRecord.kwdUpdatedData.begin(),
                                        thisRecord.kwdUpdatedData.end());

                    makeDbusCall<std::string>((INVENTORY_PATH + objectPath),
                                              commonInterface.key(),
                                              ciPropertyList.key(), kwdData);
                }
            }
        }
    }
}

void EditorImpl::processAndUpdateEI(const nlohmann::json& Inventory,
                                    const inventory::Path& objPath)
{
    for (const auto& extraInterface : Inventory["extraInterfaces"].items())
    {
        if (extraInterface.value() != NULL)
        {
            for (const auto& eiPropertyList : extraInterface.value().items())
            {
                if (eiPropertyList.value().type() ==
                    nlohmann::json::value_t::object)
                {
                    if ((eiPropertyList.value().value("recordName", "") ==
                         thisRecord.recName) &&
                        ((eiPropertyList.value().value("keywordName", "") ==
                          thisRecord.recKWd)))
                    {
                        std::string kwdData(thisRecord.kwdUpdatedData.begin(),
                                            thisRecord.kwdUpdatedData.end());
                        makeDbusCall<std::string>(
                            (INVENTORY_PATH + objPath), extraInterface.key(),
                            eiPropertyList.key(),
                            encodeKeyword(kwdData, eiPropertyList.value().value(
                                                       "encoding", "")));
                    }
                }
            }
        }
    }
}

void EditorImpl::updateCache()
{
    const std::vector<nlohmann::json>& groupEEPROM =
        jsonFile["frus"][vpdFilePath].get_ref<const nlohmann::json::array_t&>();

    // iterate through all the inventories for this file path
    for (const auto& singleInventory : groupEEPROM)
    {
        // by default inherit property is true
        bool isInherit = true;

        if (singleInventory.find("inherit") != singleInventory.end())
        {
            isInherit = singleInventory["inherit"].get<bool>();
        }

        if (isInherit)
        {
            // update com interface
            makeDbusCall<Binary>(
                (INVENTORY_PATH +
                 singleInventory["inventoryPath"].get<std::string>()),
                (IPZ_INTERFACE + (std::string) "." + thisRecord.recName),
                thisRecord.recKWd, thisRecord.kwdUpdatedData);

            // process Common interface
            processAndUpdateCI(singleInventory["inventoryPath"]
                                   .get_ref<const nlohmann::json::string_t&>());
        }

        // process extra interfaces
        processAndUpdateEI(singleInventory,
                           singleInventory["inventoryPath"]
                               .get_ref<const nlohmann::json::string_t&>());
    }
}

void EditorImpl::expandLocationCode(const std::string& locationCodeType)
{
    std::string propertyFCorTM{};
    std::string propertySE{};

    if (locationCodeType == "fcs")
    {
        propertyFCorTM =
            readBusProperty(SYSTEM_OBJECT, "com.ibm.ipzvpd.VCEN", "FC");
        propertySE =
            readBusProperty(SYSTEM_OBJECT, "com.ibm.ipzvpd.VCEN", "SE");
    }
    else if (locationCodeType == "mts")
    {
        propertyFCorTM =
            readBusProperty(SYSTEM_OBJECT, "com.ibm.ipzvpd.VSYS", "TM");
        propertySE =
            readBusProperty(SYSTEM_OBJECT, "com.ibm.ipzvpd.VSYS", "SE");
    }

    const nlohmann::json& groupFRUS =
        jsonFile["frus"].get_ref<const nlohmann::json::object_t&>();
    for (const auto& itemFRUS : groupFRUS.items())
    {
        const std::vector<nlohmann::json>& groupEEPROM =
            itemFRUS.value().get_ref<const nlohmann::json::array_t&>();
        for (const auto& itemEEPROM : groupEEPROM)
        {
            // check if the given item implements location code interface
            if (itemEEPROM["extraInterfaces"].find(LOCATION_CODE_INF) !=
                itemEEPROM["extraInterfaces"].end())
            {
                const std::string& unexpandedLocationCode =
                    itemEEPROM["extraInterfaces"][LOCATION_CODE_INF]
                              ["LocationCode"]
                                  .get_ref<const nlohmann::json::string_t&>();
                std::size_t idx = unexpandedLocationCode.find(locationCodeType);
                if (idx != std::string::npos)
                {
                    std::string expandedLoctionCode(unexpandedLocationCode);

                    if (locationCodeType == "fcs")
                    {
                        expandedLoctionCode.replace(
                            idx, 3,
                            propertyFCorTM.substr(0, 4) + ".ND0." + propertySE);
                    }
                    else if (locationCodeType == "mts")
                    {
                        std::replace(propertyFCorTM.begin(),
                                     propertyFCorTM.end(), '-', '.');
                        expandedLoctionCode.replace(
                            idx, 3, propertyFCorTM + "." + propertySE);
                    }

                    // update the DBUS interface
                    makeDbusCall<std::string>(
                        (INVENTORY_PATH +
                         itemEEPROM["inventoryPath"]
                             .get_ref<const nlohmann::json::string_t&>()),
                        LOCATION_CODE_INF, "LocationCode", expandedLoctionCode);
                }
            }
        }
    }
}

void EditorImpl::updateKeyword(const Binary& kwdData)
{

#ifndef ManagerTest
    vpdFileStream.open(vpdFilePath,
                       std::ios::in | std::ios::out | std::ios::binary);

    if (!vpdFileStream)
    {
        throw std::runtime_error("unable to open vpd file to edit");
    }

    Binary completeVPDFile((std::istreambuf_iterator<char>(vpdFileStream)),
                           std::istreambuf_iterator<char>());
    vpdFile = completeVPDFile;
#else
    Binary completeVPDFile = vpdFile;
#endif
    if (vpdFile.empty())
    {
        throw std::runtime_error("Invalid File");
    }

    auto iterator = vpdFile.cbegin();
    std::advance(iterator, IPZ_DATA_START);

    Byte vpdType = *iterator;
    if (vpdType == KW_VAL_PAIR_START_TAG)
    {
        openpower::vpd::keyword::editor::processHeader(
            std::move(completeVPDFile));

        // process VTOC for PTT rkwd
        readVTOC();

        // check record for keywrod
        checkRecordForKwd();

        // update the data to the file
        updateData(kwdData);

        // update the ECC data for the record once data has been updated
        updateRecordECC();
#ifndef ManagerTest
        // update the cache once data has been updated
        updateCache();
#endif
        return;
    }
}

} // namespace editor
} // namespace manager
} // namespace vpd
} // namespace openpower

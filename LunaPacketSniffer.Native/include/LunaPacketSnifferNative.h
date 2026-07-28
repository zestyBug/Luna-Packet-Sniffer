#pragma once

#include <cstdint>

#ifdef _WIN32
#define PC_API __declspec(dllexport)
#else
#define PC_API
#endif

extern "C"
{
    struct PcPacket
    {
        const std::uint8_t* data;
        std::uint32_t length;
        std::int64_t timestamp_unix_nanoseconds;
        std::uint8_t direction;
        std::uint32_t interface_index;
    };

    using PcPacketCallback = void (*)(void* context, const PcPacket* packet);

    struct PcFlowEvent
    {
        std::uint32_t process_id;
        std::uint8_t protocol;
        std::uint8_t event_type;
        std::uint8_t address_length;
        const std::uint8_t* local_address;
        const std::uint8_t* remote_address;
        std::uint16_t local_port;
        std::uint16_t remote_port;
    };

    using PcFlowCallback = void (*)(void* context, const PcFlowEvent* flow_event);

    PC_API int PcCaptureStart(
        const char* filter,
        PcPacketCallback callback,
        PcFlowCallback flow_callback,
        void* context,
        void** capture_handle,
        int* failure_stage);

    PC_API void PcCaptureStop(void* capture_handle);

}

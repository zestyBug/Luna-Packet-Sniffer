#include "LunaPacketSnifferNative.h"

#include <windows.h>
#include <windivert.h>

#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

namespace
{
    struct CaptureContext
    {
        HANDLE handle = INVALID_HANDLE_VALUE;
        HANDLE flow_handle = INVALID_HANDLE_VALUE;
        PcPacketCallback callback = nullptr;
        PcFlowCallback flow_callback = nullptr;
        void* callback_context = nullptr;
        std::atomic_bool stopping = false;
        std::thread receive_thread;
        std::thread flow_thread;
    };

    std::int64_t GetUnixNanoseconds()
    {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    }

    void ReceivePackets(CaptureContext& context)
    {
        std::array<std::uint8_t, 0xFFFF> buffer{};
        while (!context.stopping.load(std::memory_order_relaxed))
        {
            UINT received_length = 0;
            WINDIVERT_ADDRESS address{};
            if (!WinDivertRecv(context.handle, buffer.data(), static_cast<UINT>(buffer.size()), &received_length, &address))
            {
                if (context.stopping.load(std::memory_order_relaxed))
                {
                    return;
                }

                continue;
            }

            const PcPacket packet{
                .data = buffer.data(),
                .length = received_length,
                .timestamp_unix_nanoseconds = GetUnixNanoseconds(),
                .direction = static_cast<std::uint8_t>(address.Outbound),
                .interface_index = address.Network.IfIdx,
            };
            context.callback(context.callback_context, &packet);
        }
    }

    void ReceiveFlowEvents(CaptureContext& context)
    {
        while (!context.stopping.load(std::memory_order_relaxed))
        {
            WINDIVERT_ADDRESS address{};
            if (!WinDivertRecv(context.flow_handle, nullptr, 0, nullptr, &address))
            {
                if (context.stopping.load(std::memory_order_relaxed))
                {
                    return;
                }

                continue;
            }

            const auto event_type = static_cast<std::uint8_t>(address.Event);
            if (event_type != WINDIVERT_EVENT_FLOW_ESTABLISHED && event_type != WINDIVERT_EVENT_FLOW_DELETED)
            {
                continue;
            }

            std::array<std::uint32_t, 4> local_address{};
            std::array<std::uint32_t, 4> remote_address{};
            if (address.IPv6)
            {
                WinDivertHelperHtonIPv6Address(address.Flow.LocalAddr, local_address.data());
                WinDivertHelperHtonIPv6Address(address.Flow.RemoteAddr, remote_address.data());
            }
            else
            {
                local_address[0] = WinDivertHelperHtonl(address.Flow.LocalAddr[0]);
                remote_address[0] = WinDivertHelperHtonl(address.Flow.RemoteAddr[0]);
            }

            const PcFlowEvent flow_event{
                .process_id = address.Flow.ProcessId,
                .protocol = address.Flow.Protocol,
                .event_type = event_type,
                .address_length = static_cast<std::uint8_t>(address.IPv6 ? 16 : 4),
                .local_address = reinterpret_cast<const std::uint8_t*>(local_address.data()),
                .remote_address = reinterpret_cast<const std::uint8_t*>(remote_address.data()),
                .local_port = address.Flow.LocalPort,
                .remote_port = address.Flow.RemotePort,
            };
            context.flow_callback(context.callback_context, &flow_event);
        }
    }
}

int PcCaptureStart(
    const char* filter,
    PcPacketCallback callback,
    PcFlowCallback flow_callback,
    void* context,
    void** capture_handle,
    int* failure_stage)
{
    if (filter == nullptr || callback == nullptr || flow_callback == nullptr || capture_handle == nullptr || failure_stage == nullptr)
    {
        return ERROR_INVALID_PARAMETER;
    }

    *failure_stage = 0;
    auto capture = std::make_unique<CaptureContext>();
    capture->callback = callback;
    capture->callback_context = context;
    capture->handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
    if (capture->handle == INVALID_HANDLE_VALUE)
    {
        *failure_stage = 1;
        return static_cast<int>(GetLastError());
    }

    capture->flow_callback = flow_callback;
    capture->flow_handle = WinDivertOpen("true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (capture->flow_handle == INVALID_HANDLE_VALUE)
    {
        *failure_stage = 2;
        const auto error = static_cast<int>(GetLastError());
        WinDivertClose(capture->handle);
        return error;
    }

    capture->receive_thread = std::thread(ReceivePackets, std::ref(*capture));
    capture->flow_thread = std::thread(ReceiveFlowEvents, std::ref(*capture));
    *capture_handle = capture.release();
    return ERROR_SUCCESS;
}

void PcCaptureStop(void* capture_handle)
{
    if (capture_handle == nullptr)
    {
        return;
    }

    std::unique_ptr<CaptureContext> context(static_cast<CaptureContext*>(capture_handle));
    context->stopping.store(true, std::memory_order_relaxed);
    WinDivertShutdown(context->handle, WINDIVERT_SHUTDOWN_RECV);
    WinDivertShutdown(context->flow_handle, WINDIVERT_SHUTDOWN_RECV);
    if (context->receive_thread.joinable())
    {
        context->receive_thread.join();
    }

    if (context->flow_thread.joinable())
    {
        context->flow_thread.join();
    }

    WinDivertClose(context->handle);
    WinDivertClose(context->flow_handle);
}

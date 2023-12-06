# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


add_quic_tool(quicsample sample.c)
add_quic_tool(quic_sample_server server.cpp)
add_quic_tool(quic_sample_client client.cpp)
quic_tool_warnings(quicsample)

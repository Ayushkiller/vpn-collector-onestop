/*
 * This file is part of PCAPdroid (research fork: VPN-Detect Collector).
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Copyright 2020-25 - Emanuele Faranda
 * Fork additions 2026 - DTU VPN-Detect campaign
 */

package com.emanuelef.remote_capture.pcap_dump;

import android.util.Log;

import com.emanuelef.remote_capture.CaptureService;
import com.emanuelef.remote_capture.Utils;
import com.emanuelef.remote_capture.interfaces.PcapDumper;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Iterator;
import java.util.Locale;

/**
 * Streams the live header-only PCAP to the research collector over a single HTTP POST
 * using chunked transfer-encoding. Records are written as they arrive, so a capture that
 * is stopped (or interrupted when the user turns on their own VPN) still yields a valid,
 * truncated PCAP on the server. The socket is protect()ed so the upload traffic itself is
 * never captured (avoids a feedback loop) without relying on a BPF.
 *
 * No payload is transmitted: PCAPdroid is configured header-only upstream; this dumper only
 * forwards whatever the capture core produced.
 */
public class HttpDumper implements PcapDumper {
    private static final String TAG = "HttpDumper";

    // Shared anti-abuse token (also enforced server-side). Not a strong secret — it only
    // blocks casual/bot POSTs to the public endpoint.
    private static final String TOKEN = "vrp-collect-2026-x7k2";

    private final InetSocketAddress mServer;
    private final boolean mPcapngFormat;
    private boolean mSendHeader;
    private Socket mSocket;
    private OutputStream mOut;

    public HttpDumper(InetSocketAddress server, boolean pcapngFormat) {
        mServer = server;
        mPcapngFormat = pcapngFormat;
        mSendHeader = true;
    }

    @Override
    public void startDumper() throws IOException {
        mSocket = new Socket();
        boolean ok = false;
        try {
            mSocket.connect(mServer, 3000);
            CaptureService.requireInstance().protect(mSocket);
            mOut = mSocket.getOutputStream();

            String ts   = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new java.util.Date());
            // Single-VPN constraint: when this app captures, it IS the only VPN, so the
            // traffic is the device's normal (non-VPN) traffic -> label nonvpn.
            String name = "nonvpn_mobile_" + ts + ".pcap";
            String host = mServer.getAddress().getHostAddress() + ":" + mServer.getPort();

            String req = "POST /?name=" + name + "&t=" + TOKEN + " HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "Content-Type: application/octet-stream\r\n"
                    + "Transfer-Encoding: chunked\r\n"
                    + "Connection: close\r\n\r\n";
            mOut.write(req.getBytes(StandardCharsets.US_ASCII));
            mOut.flush();
            ok = true;
        } finally {
            if (!ok && mSocket != null) mSocket.close();
        }
    }

    @Override
    public void stopDumper() throws IOException {
        try {
            if (mOut != null) {
                mOut.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII)); // terminating chunk
                mOut.flush();
            }
        } catch (IOException ignored) {
        } finally {
            try { if (mOut != null) mOut.close(); } finally { if (mSocket != null) mSocket.close(); }
        }
    }

    @Override
    public String getBpf() {
        return "not (host " + mServer.getAddress().getHostAddress() + " and tcp port " + mServer.getPort() + ")";
    }

    private void writeChunk(byte[] data, int off, int len) throws IOException {
        if (len <= 0) return;
        mOut.write((Integer.toHexString(len) + "\r\n").getBytes(StandardCharsets.US_ASCII));
        mOut.write(data, off, len);
        mOut.write("\r\n".getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public void dumpData(byte[] data) throws IOException {
        if (mSendHeader) {
            mSendHeader = false;
            byte[] hdr = CaptureService.getPcapHeader();
            writeChunk(hdr, 0, hdr.length);
        }

        // Forward exactly the PCAP record bytes the core produced.
        Iterator<Integer> it = Utils.iterPcapRecords(data, mPcapngFormat);
        int pos = 0;
        while (it.hasNext()) {
            int rec_len = it.next();
            writeChunk(data, pos, rec_len);
            pos += rec_len;
        }
        mOut.flush();
    }
}

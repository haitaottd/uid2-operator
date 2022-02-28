package com.uid2.operator.vertx;

import com.uid2.operator.service.EncryptionHelper;
import com.uid2.operator.service.ResponseUtil;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.store.IClientKeyProvider;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

public class V2PayloadHandler {
    private static final io.vertx.core.logging.Logger LOGGER = LoggerFactory.getLogger(V2PayloadHandler.class);

    // version: 1 byte, IV: 16 bytes, GCM tag: 12 bytes, timestamp: 8 bytes, nonce: 8 bytes
    private static final int MIN_PAYLOAD_LENGTH = 1 + 16 + EncryptionHelper.GCM_TAG_LENGTH + 8 + 8;

    private static final byte VERSION = 1;

    private final IClientKeyProvider clientKeyProvider;

    private final Clock clock;

    public V2PayloadHandler(IClientKeyProvider clientKeyProvider, Clock clock) {
        this.clientKeyProvider = clientKeyProvider;
        this.clock = clock;
    }

    public void handle(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        ClientKey ck = AuthMiddleware.getAuthClient(ClientKey.class, rc);

        // Encrypted body format:
        //  byte 1: version
        //  byte 2-16: IV
        //  byte 17-end: encrypted payload
        byte[] bodyBytes = Utils.decodeBase64String(rc.getBodyAsString());
        if (!sanityCheck(bodyBytes, MIN_PAYLOAD_LENGTH)) {
            ResponseUtil.ClientError(rc, "wrong format");
            return;
        }

        // Decrypted format:
        //  byte 0-7: timestamp
        //  byte 8-15: nonce
        //  byte 16-end: base64 encoded request json
        byte[] decryptedBody;
        try {
            decryptedBody = EncryptionHelper.decryptGCM(bodyBytes, 1, ck.getSecretBytes());
        }
        catch (Exception ex) {
            ResponseUtil.ClientError(rc, "fail to decrypt");
            return;
        }

        Buffer b = Buffer.buffer(decryptedBody);
        Instant tm = Instant.ofEpochMilli(b.getLong(0));
        if (Math.abs(Duration.between(tm, Instant.now(clock)).toMinutes()) > 1.0) {
            ResponseUtil.ClientError(rc, "invalid timestamp");
            return;
        }

        if (decryptedBody.length > 16) {
            String bodyStr = new String(decryptedBody, 16, decryptedBody.length - 16, StandardCharsets.UTF_8);
            JsonObject reqJson = new JsonObject(bodyStr);
            rc.data().put("request", reqJson);
        }

        apiHandler.handle(rc);

        if (rc.statusCode() != -1) {
            assert rc.statusCode() != 200;
            return;
        }

        JsonObject respJson = (JsonObject) rc.data().get("response");
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/octet-stream");
        rc.response().end(Utils.toBase64String(EncryptionHelper.encryptGCM(respJson.encode().getBytes(StandardCharsets.UTF_8), ck.getSecretBytes())));
    }

    private boolean sanityCheck(byte[] buf, int minLength) {
        if (buf.length < minLength) {
            return false;
        }

        if (buf[0] != VERSION) {
            return false;
        }

        return true;
    }
}


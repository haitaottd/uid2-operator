// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.shared.model.SaltEntry;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.shared.store.ISaltProvider;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class UIDOperatorService implements IUIDOperatorService {
    public static final String IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS = "identity_token_expires_after_seconds";
    public static final String REFRESH_TOKEN_EXPIRES_AFTER_SECONDS = "refresh_token_expires_after_seconds";
    public static final String REFRESH_IDENTITY_TOKEN_AFTER_SECONDS = "refresh_identity_token_after_seconds";

    private static final Instant RefreshCutoff = LocalDateTime.parse("2021-03-08T17:00:00", DateTimeFormatter.ISO_LOCAL_DATE_TIME).toInstant(ZoneOffset.UTC);
    private final ISaltProvider saltProvider;
    private final IOptOutStore optOutStore;
    private final ITokenEncoder encoder;
    private final Clock clock;
    private final UserIdentity testOptOutIdentity;

    private final Duration identityExpiresAfter;
    private final Duration refreshExpiresAfter;
    private final Duration refreshIdentityAfter;

    private final OperatorIdentity operatorIdentity;
    private final TokenVersion tokenVersion;
    private final boolean uid2EmailV3Enabled;

    public UIDOperatorService(JsonObject config, IOptOutStore optOutStore, ISaltProvider saltProvider, ITokenEncoder encoder, Clock clock) {
        this.saltProvider = saltProvider;
        this.encoder = encoder;
        this.optOutStore = optOutStore;
        this.clock = clock;

        this.testOptOutIdentity = getFirstLevelHashIdentity(IdentityScope.UID2, IdentityType.Email,
                InputUtil.NormalizeEmail("optout@email.com").getIdentityInput(), Instant.now());
        this.operatorIdentity = new OperatorIdentity(0, OperatorType.Service, 0, 0);

        this.identityExpiresAfter = Duration.ofSeconds(config.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        this.refreshExpiresAfter = Duration.ofSeconds(config.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS));
        this.refreshIdentityAfter = Duration.ofSeconds(config.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS));

        if (this.identityExpiresAfter.compareTo(this.refreshExpiresAfter) > 0) {
            throw new IllegalStateException(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        }
        if (this.refreshIdentityAfter.compareTo(this.identityExpiresAfter) > 0) {
            throw new IllegalStateException(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        }
        if (this.refreshIdentityAfter.compareTo(this.refreshExpiresAfter) > 0) {
            throw new IllegalStateException(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        }

        this.tokenVersion = config.getBoolean("generate_v3_tokens", false) ? TokenVersion.V3 : TokenVersion.V2;
        this.uid2EmailV3Enabled = config.getBoolean("uid2_email_v3", false);
    }

    @Override
    public IdentityTokens generateIdentity(IdentityRequest request) {
        final Instant now = EncodingUtils.NowUTCMillis(this.clock);
        final byte[] firstLevelHash = getFirstLevelHash(request.userIdentity.id, now);
        final UserIdentity firstLevelHashIdentity = new UserIdentity(
                request.userIdentity.identityScope, request.userIdentity.identityType, firstLevelHash, request.userIdentity.privacyBits,
                request.userIdentity.establishedAt, request.userIdentity.refreshedAt);
        return generateIdentity(request.publisherIdentity, firstLevelHashIdentity);
    }

    @Override
    public RefreshResponse refreshIdentity(String refreshToken) {
        final RefreshToken token;
        try {
            token = this.encoder.decodeRefreshToken(refreshToken);
        } catch (Throwable t) {
            return RefreshResponse.Invalid;
        }
        if (token == null) {
            return RefreshResponse.Invalid;
        }

        if (token.userIdentity.establishedAt.isBefore(RefreshCutoff)) {
            return RefreshResponse.Deprecated;
        }

        if (token.expiresAt.isBefore(Instant.now(this.clock))) {
            return RefreshResponse.Expired;
        }

        if (token.userIdentity.matches(testOptOutIdentity)) {
            return RefreshResponse.Optout;
        }

        try {
            final Instant logoutEntry = this.optOutStore.getLatestEntry(token.userIdentity);

            if (logoutEntry == null || token.userIdentity.establishedAt.isAfter(logoutEntry)) {
                return RefreshResponse.Refreshed(this.generateIdentity(token.publisherIdentity, token.userIdentity));
            } else {
                return RefreshResponse.Optout;
            }
        } catch (Exception ex) {
            return RefreshResponse.Invalid;
        }
    }

    @Override
    public MappedIdentity map(UserIdentity userIdentity, Instant asOf) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        return getAdvertisingId(firstLevelHashIdentity, asOf);
    }

    @Override
    public List<SaltEntry> getModifiedBuckets(Instant sinceTimestamp) {
        return this.saltProvider.getSnapshot(Instant.now()).getModifiedSince(sinceTimestamp);
    }

    @Override
    public void invalidateTokensAsync(UserIdentity userIdentity, Instant asOf, Handler<AsyncResult<Instant>> handler) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        final MappedIdentity mappedIdentity = getAdvertisingId(firstLevelHashIdentity, asOf);

        this.optOutStore.addEntry(firstLevelHashIdentity, mappedIdentity.advertisingId, r -> {
            if (r.succeeded()) {
                handler.handle(Future.succeededFuture(r.result()));
            } else {
                handler.handle(Future.failedFuture(r.cause()));
            }
        });
    }

    @Override
    public boolean advertisingTokenMatches(String advertisingToken, UserIdentity userIdentity, Instant asOf) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        final MappedIdentity mappedIdentity = getAdvertisingId(firstLevelHashIdentity, asOf);

        final AdvertisingToken token = this.encoder.decodeAdvertisingToken(advertisingToken);
        return Arrays.equals(mappedIdentity.advertisingId, token.userIdentity.id);
    }

    @Override
    public Instant getLatestOptoutEntry(UserIdentity userIdentity, Instant asOf) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        return this.optOutStore.getLatestEntry(firstLevelHashIdentity);
    }

    private UserIdentity getFirstLevelHashIdentity(UserIdentity userIdentity, Instant asOf) {
        return getFirstLevelHashIdentity(userIdentity.identityScope, userIdentity.identityType, userIdentity.id, asOf);
    }

    private UserIdentity getFirstLevelHashIdentity(IdentityScope identityScope, IdentityType identityType, byte[] identityHash, Instant asOf) {
        final byte[] firstLevelHash = getFirstLevelHash(identityHash, asOf);
        return new UserIdentity(identityScope, identityType, firstLevelHash, 0, null, null);
    }

    private byte[] getFirstLevelHash(byte[] identityHash, Instant asOf) {
        return TokenUtils.getFirstLevelHash(identityHash, this.saltProvider.getSnapshot(asOf).getFirstLevelSalt());
    }

    private MappedIdentity getAdvertisingId(UserIdentity firstLevelHashIdentity, Instant asOf) {
        final SaltEntry rotatingSalt = this.saltProvider.getSnapshot(asOf).getRotatingSalt(firstLevelHashIdentity.id);

        return new MappedIdentity(
                this.uid2EmailV3Enabled
                    ? TokenUtils.getAdvertisingIdV3(firstLevelHashIdentity.identityScope, firstLevelHashIdentity.identityType, firstLevelHashIdentity.id, rotatingSalt.getSalt())
                    : TokenUtils.getAdvertisingIdV2(firstLevelHashIdentity.id, rotatingSalt.getSalt()),
                rotatingSalt.getHashedId());
    }

    private IdentityTokens generateIdentity(PublisherIdentity publisherIdentity, UserIdentity firstLevelHashIdentity) {
        final Instant nowUtc = EncodingUtils.NowUTCMillis(this.clock);

        final MappedIdentity mappedIdentity = getAdvertisingId(firstLevelHashIdentity, nowUtc);
        final UserIdentity advertisingIdentity = new UserIdentity(firstLevelHashIdentity.identityScope, firstLevelHashIdentity.identityType,
                mappedIdentity.advertisingId, firstLevelHashIdentity.privacyBits, firstLevelHashIdentity.establishedAt, nowUtc);

        return this.encoder.encode(
                this.createAdvertisingToken(publisherIdentity, advertisingIdentity, nowUtc),
                this.createUserToken(publisherIdentity, advertisingIdentity, nowUtc),
                this.createRefreshToken(publisherIdentity, firstLevelHashIdentity, nowUtc),
                nowUtc.plusMillis(refreshIdentityAfter.toMillis()),
                nowUtc
        );
    }

    private RefreshToken createRefreshToken(PublisherIdentity publisherIdentity, UserIdentity userIdentity, Instant now) {
        return new RefreshToken(
                tokenVersion,
                now,
                now.plusMillis(refreshExpiresAfter.toMillis()),
                this.operatorIdentity,
                publisherIdentity,
                userIdentity);
    }

    private AdvertisingToken createAdvertisingToken(PublisherIdentity publisherIdentity, UserIdentity userIdentity, Instant now) {
        return new AdvertisingToken(
                tokenVersion,
                now,
                now.plusMillis(identityExpiresAfter.toMillis()),
                this.operatorIdentity,
                publisherIdentity,
                userIdentity);
    }

    private UserToken createUserToken(PublisherIdentity publisherIdentity, UserIdentity userIdentity, Instant now) {
        return new UserToken(
                TokenVersion.V2,
                now,
                now.plusMillis(identityExpiresAfter.toMillis()),
                this.operatorIdentity,
                publisherIdentity,
                userIdentity);
    }

}

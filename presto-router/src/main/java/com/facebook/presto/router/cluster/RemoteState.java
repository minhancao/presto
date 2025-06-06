/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.router.cluster;

import com.facebook.airlift.http.client.FullJsonResponseHandler;
import com.facebook.airlift.http.client.HttpClient;
import com.facebook.airlift.http.client.Request;
import com.facebook.airlift.json.JsonCodec;
import com.facebook.airlift.log.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import io.airlift.units.Duration;

import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;

import java.net.URI;
import java.time.Instant;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static com.facebook.airlift.http.client.FullJsonResponseHandler.createFullJsonResponseHandler;
import static com.facebook.airlift.http.client.HttpStatus.OK;
import static com.facebook.airlift.http.client.Request.Builder.prepareGet;
import static com.facebook.airlift.json.JsonCodec.jsonCodec;
import static com.google.common.util.concurrent.MoreExecutors.directExecutor;
import static io.airlift.units.Duration.nanosSince;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.SECONDS;

@ThreadSafe
public abstract class RemoteState
{
    private static final Logger log = Logger.get(RemoteState.class);
    private static final JsonCodec<JsonNode> JSON_CODEC = jsonCodec(JsonNode.class);

    private final HttpClient httpClient;
    private final URI remoteUri;
    private final AtomicReference<Future<?>> future = new AtomicReference<>();
    private final AtomicLong lastUpdateNanos = new AtomicLong();
    private final AtomicLong lastWarningLogged = new AtomicLong();
    private final Duration clusterUnhealthyTimeout;

    private AtomicBoolean isHealthy;
    private volatile Instant lastHealthyResponseTime = Instant.now();

    @Inject
    public RemoteState(HttpClient httpClient, URI remoteUri, RemoteStateConfig remoteStateConfig)
    {
        this.isHealthy = new AtomicBoolean(true);
        this.httpClient = requireNonNull(httpClient, "httpClient is null");
        this.remoteUri = requireNonNull(remoteUri, "remoteUri is null");
        this.clusterUnhealthyTimeout = remoteStateConfig.getClusterUnhealthyTimeout();
    }

    public void handleResponse(JsonNode response) {}

    public synchronized void asyncRefresh()
    {
        Duration sinceUpdate = nanosSince(lastUpdateNanos.get());

        if (nanosSince(lastWarningLogged.get()).toMillis() > 1_000 &&
                sinceUpdate.toMillis() > 10_000 &&
                future.get() != null) {
            log.warn(
                    "Coordinator update request to %s:%d has not returned in %s",
                    remoteUri.getHost(), remoteUri.getPort(), sinceUpdate.toString(SECONDS));
            lastWarningLogged.set(System.nanoTime());
        }

        if (nanosSince(lastHealthyResponseTime.toEpochMilli()).toMillis() > clusterUnhealthyTimeout.toMillis() && isHealthy.get()) {
            isHealthy.set(false);
            log.warn("%s:%d marked as unhealthy", remoteUri.getHost(), remoteUri.getPort());
        }

        if (sinceUpdate.toMillis() > 1_000 && future.get() == null) {
            Request request = prepareGet()
                    .setUri(remoteUri)
                    .build();

            HttpClient.HttpResponseFuture<FullJsonResponseHandler.JsonResponse<JsonNode>> responseFuture = httpClient.executeAsync(request, createFullJsonResponseHandler(JSON_CODEC));
            future.compareAndSet(null, responseFuture);

            Futures.addCallback(responseFuture, new FutureCallback<FullJsonResponseHandler.JsonResponse<JsonNode>>()
            {
                @Override
                public void onSuccess(@Nullable FullJsonResponseHandler.JsonResponse<JsonNode> result)
                {
                    lastUpdateNanos.set(System.nanoTime());
                    future.compareAndSet(responseFuture, null);
                    if (result != null) {
                        if (result.hasValue()) {
                            handleResponse(result.getValue());
                        }
                        if (result.getStatusCode() != OK.code()) {
                            log.debug("Error fetching node state from %s returned status code %d", remoteUri, result.getStatusCode());
                        }
                        else {
                            if (!isHealthy.get()) {
                                log.debug("%s:%d was unhealthy, and is now healthy", remoteUri.getHost(), remoteUri.getPort());
                                isHealthy.set(true);
                            }
                            lastHealthyResponseTime = Instant.now();
                        }
                    }
                    else {
                        log.debug("RemoteState successful result was null");
                    }
                }

                @Override
                public void onFailure(Throwable t)
                {
                    log.warn("Error fetching query infos from %s: %s", remoteUri, t.getMessage());
                    lastUpdateNanos.set(System.nanoTime());
                    future.compareAndSet(responseFuture, null);
                }
            }, directExecutor());
        }
    }

    public boolean isHealthy()
    {
        return isHealthy.get();
    }
}

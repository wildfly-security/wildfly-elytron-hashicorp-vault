/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault.logging;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import org.jboss.logging.Logger;
import org.testcontainers.containers.output.BaseConsumer;
import org.testcontainers.containers.output.OutputFrame;

/**
 * Jboss logging based consumer for the testcontainers container.
 */
public class JbossLoggingLogConsumer extends BaseConsumer<JbossLoggingLogConsumer> {

    private final Logger logger;

    private boolean separateOutputStreams;

    private String prefix = "";

    public JbossLoggingLogConsumer(Logger logger) {
        this(logger, false);
    }

    public JbossLoggingLogConsumer(Logger logger, boolean separateOutputStreams) {
        this.logger = logger;
        this.separateOutputStreams = separateOutputStreams;
    }

    /**
     * Set prefix for each log message
     * @param prefix prefix to be used
     * @return instance of this consumer
     */
    public JbossLoggingLogConsumer withPrefix(String prefix) {
        this.prefix = "[" + prefix + "] ";
        return this;
    }

    /**
     * Use separate message levels for STDERR and STDOUT?
     * @return instance of this consumer
     */
    public JbossLoggingLogConsumer withSeparateOutputStreams() {
        this.separateOutputStreams = true;
        return this;
    }

    @Override
    public void accept(OutputFrame outputFrame) {
        final OutputFrame.OutputType outputType = outputFrame.getType();
        final String utf8String = outputFrame.getUtf8StringWithoutLineEnding();

        switch (outputType) {
            case END:
                break;
            case STDOUT:
                if (separateOutputStreams) {
                    logger.infof("%s%s", prefix.isEmpty() ? "" : (prefix + ": "), utf8String);
                } else {
                    logger.infof("%s%s: %s", prefix, outputType, utf8String);
                }
                break;
            case STDERR:
                if (separateOutputStreams) {
                    logger.errorf("%s%s", prefix.isEmpty() ? "" : (prefix + ": "), utf8String);
                } else {
                    logger.infof("%s%s: %s", prefix, outputType, utf8String);
                }
                break;
            default:
                throw ROOT_LOGGER.unexpectedTestContainerOutputType(outputType);
        }
    }


}

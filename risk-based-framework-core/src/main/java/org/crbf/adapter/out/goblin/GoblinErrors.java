package org.crbf.adapter.out.goblin;

/**
 * Error descriptions for Goblin Weaver failures.
 *
 * <p>Connection-level failures such as {@code ConnectException} carry a null
 * detail message, so logging {@code getMessage()} alone renders the most common
 * failure — the service being unreachable — as the word "null".
 */
final class GoblinErrors {

    private GoblinErrors() {
    }

    static String describe(Throwable error) {
        if (error == null) {
            return "unknown error";
        }

        String message = error.getMessage();

        return message == null || message.isBlank()
                ? error.getClass().getSimpleName()
                : error.getClass().getSimpleName() + ": " + message;
    }
}

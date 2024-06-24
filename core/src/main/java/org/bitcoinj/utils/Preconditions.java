package org.bitcoinj.utils;

public class Preconditions {

    /**
     * Ensures the truth of an expression involving one or more parameters to the calling method.
     * @param expression a boolean expression
     * @throws IllegalArgumentException if {@code expression} is false
     */
    public static void checkArgument(boolean expression) {
        check(expression, new Supplier<IllegalArgumentException>() {
            @Override
            public IllegalArgumentException get() {
                return new IllegalArgumentException();
            }
        });
    }

    /**
     * Ensures the truth of an expression involving one or more parameters to the calling method.
     * @param expression a boolean expression
     * @param messageSupplier supplier of the detail message to be used in the event that a IllegalArgumentException is thrown
     * @throws IllegalArgumentException if {@code expression} is false
     */
    public static void checkArgument(boolean expression, final Supplier<String> messageSupplier) {
        check(expression, new Supplier<IllegalArgumentException>() {
            @Override
            public IllegalArgumentException get() {
                return new IllegalArgumentException(messageSupplier.get());
            }
        });
    }

    /**
     * Ensures the truth of an expression involving the state of the calling instance, but not
     * involving any parameters to the calling method.
     * @param expression a boolean expression
     * @throws IllegalStateException if {@code expression} is false
     */
    public static void checkState(boolean expression) {
        check(expression, new Supplier<IllegalStateException>() {
            @Override
            public IllegalStateException get() {
                return new IllegalStateException();
            }
        });
    }

    /**
     * Ensures the truth of an expression involving the state of the calling instance, but not
     * involving any parameters to the calling method.
     * @param expression a boolean expression
     * @param messageSupplier supplier of the detail message to be used in the event that a IllegalStateException is thrown
     * @throws IllegalStateException if {@code expression} is false
     */
    public static void checkState(boolean expression, final Supplier<String> messageSupplier) {
        check(expression, new Supplier<IllegalStateException>() {
            @Override
            public IllegalStateException get() {
                return new IllegalStateException(messageSupplier.get());
            }
        });
    }

    /**
     * Ensures the truth of an expression, throwing a custom exception if untrue.
     * @param expression a boolean expression
     * @param exceptionSupplier supplier of the exception to be thrown
     * @throws X if {@code expression} is false
     */
    public static <X extends Throwable> void check(boolean expression, Supplier<? extends X> exceptionSupplier) throws X {
        if (!expression) {
            throw exceptionSupplier.get();
        }
    }

    // Custom Supplier interface to be compatible with Java 1.7
    public interface Supplier<T> {
        T get();
    }
}

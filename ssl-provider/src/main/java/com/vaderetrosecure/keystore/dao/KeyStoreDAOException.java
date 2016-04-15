/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

/**
 * This exception is the base class of all exception of the DAO.
 * If an exception occurs in an implementation, this exception, or a 
 * sub class of it must be thrown.<br>
 * In case of an exception is thrown be the underlying implementation, 
 * it can be the cause of this exception.
 * 
 * @author ahonore
 */
public class KeyStoreDAOException extends Exception
{
    private static final long serialVersionUID = -8696777095560829194L;

    /**
     * Construct a new KeyStoreDAOException object, given a message.
     * 
     * @param message the message of this exception.
     */
    public KeyStoreDAOException(String message)
    {
        super(message, null);
    }

    /**
     * Construct a new KeyStoreDAOException object, given a cause from an underlying implementation.
     * 
     * @param cause an exception which is the cause of this exception.
     */
    public KeyStoreDAOException(Throwable cause)
    {
        super(cause);
    }
}

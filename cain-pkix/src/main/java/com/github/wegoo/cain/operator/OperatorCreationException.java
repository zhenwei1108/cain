package com.github.wegoo.cain.operator;

public class OperatorCreationException
    extends OperatorException
{
    public OperatorCreationException(String msg, Throwable cause)
    {
        super(msg, cause);
    }

    public OperatorCreationException(String msg)
    {
        super(msg);
    }
}

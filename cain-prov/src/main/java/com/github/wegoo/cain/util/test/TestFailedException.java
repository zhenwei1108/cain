package com.github.wegoo.cain.util.test;

public class TestFailedException 
    extends RuntimeException
{
    private TestResult _result;
    
    public TestFailedException(
        TestResult result)
    {
        _result = result;
    }
    
    public TestResult getResult()
    {
        return _result;
    }
}

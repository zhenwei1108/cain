package com.github.wegoo.cain.tsp.ers;

import java.util.Date;

import com.github.wegoo.cain.util.Selector;

public class ERSEvidenceRecordSelector
    implements Selector<ERSEvidenceRecord>
{
    private final ERSData data;
    private final Date date;

    public ERSEvidenceRecordSelector(ERSData data)
    {
        this(data, new Date());
    }

    public ERSEvidenceRecordSelector(ERSData data, Date atDate)
    {
        this.data = data;
        this.date = new Date(atDate.getTime());
    }

    public ERSData getData()
    {
        return data;
    }

    public boolean match(ERSEvidenceRecord obj)
    {
        try
        {
            if (obj.isContaining(data, date))
            {
                try
                {
                    obj.validatePresent(data, date);

                    return true;
                }
                catch (Exception e)
                {
                    return false;
                }
            }

            return false;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    public Object clone()
    {
        return this;
    }
}

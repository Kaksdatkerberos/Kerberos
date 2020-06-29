using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Kerberos
{
    interface IProcessingBehavior
    {
        byte[] ProcessData(byte[] data, int numberOfBytesRead);
    }
}

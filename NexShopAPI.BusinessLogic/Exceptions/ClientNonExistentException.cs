using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.BusinessLogic.Exceptions
{
    public class ClientNonExistentException: Exception
    {
        public ClientNonExistentException()
        {
            
        }

        public ClientNonExistentException(int id):
            base(String.Format("The Client with the id '{0}' does not exist.", id))
        {
            
        }
    }
}

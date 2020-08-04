using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;

namespace Opc.Ua
{
    public partial class NodeState
    {
        public string Specification { get; set; }
    }

    public partial class StructureDefinition
    {
        public int FirstExplicitFieldIndex { get; set; }
    }

    public partial class NodeStateCollection
    {
        /// <summary>
        /// Writes the collection to a stream using the Opc.Ua.Schema.UANodeSet schema.
        /// </summary>
        public void SaveAsNodeSet2(
            ISystemContext context,
            Stream ostrm,
            Export.ModelTableEntry model,
            DateTime lastModified,
            bool outputRedundantNames)
        {
            Opc.Ua.Export.UANodeSet nodeSet = new Opc.Ua.Export.UANodeSet();

            if (lastModified != DateTime.MinValue)
            {
                nodeSet.LastModified = lastModified;
                nodeSet.LastModifiedSpecified = true;
            }

            if (model != null)
            {
                nodeSet.Models = new Export.ModelTableEntry[] { model };
            }

            for (int ii = 0; ii < s_AliasesToUse.Length; ii++)
            {
                nodeSet.AddAlias(context, s_AliasesToUse[ii].Alias, s_AliasesToUse[ii].NodeId);
            }

            for (int ii = 0; ii < this.Count; ii++)
            {
                nodeSet.Export(context, this[ii], outputRedundantNames);
            }

            nodeSet.Write(ostrm);
        }
    }
}

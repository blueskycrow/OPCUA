/* ========================================================================
 * Copyright (c) 2005-2017 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Xml;
using System.Linq;
using System.Xml.Linq;
using System.IO;
using System.Threading;
using System.Reflection;
using Opc.Ua;
using Opc.Ua.Server;
using Opc.Ua.MTConnect;

namespace Quickstarts.Boiler.Server
{
    /// <summary>
    /// Defines a method of loading XML as a tree
    /// </summary>
    ///public static System.Xml.Linq.XElement Load(System.IO.TextReader textReader, System.Xml.Linq.LoadOptions options);

    /// <summary>
    /// A node manager for a server that exposes several variables.
    /// </summary>
    public class BoilerNodeManager : CustomNodeManager2
    {
        #region Constructors
        /// <summary>
        /// Initializes the node manager.
        /// </summary>
        public BoilerNodeManager(IServerInternal server, ApplicationConfiguration configuration)
        :
            base(server, configuration)
        {
            SystemContext.NodeIdFactory = this;

            // set one namespace for the type model and one names for dynamically created nodes.
            string[] namespaceUrls = new string[3];
            namespaceUrls[0] = Namespaces.Boiler;
            namespaceUrls[1] = Namespaces.Boiler + "/Instance";
            namespaceUrls[2] = "http://opcfoundation.org/UA/MTConnect/";
            SetNamespaces(namespaceUrls);

            // get the configuration for the node manager.
            m_configuration = configuration.ParseExtension<BoilerServerConfiguration>();

            // use suitable defaults if no configuration exists.
            if (m_configuration == null)
            {
                m_configuration = new BoilerServerConfiguration();
            }
        }
        #endregion

        #region IDisposable Members
        /// <summary>
        /// An overrideable version of the Dispose.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (m_simulationTimer != null)
                {
                    Utils.SilentDispose(m_simulationTimer);
                    m_simulationTimer = null;
                }
            }
        }
        #endregion

        #region INodeIdFactory Members
        /// <summary>
        /// Creates the NodeId for the specified node.
        /// </summary>
        public override NodeId New(ISystemContext context, NodeState node)
        {
            // generate a new numeric id in the instance namespace.
            return new NodeId(++m_nodeIdCounter, NamespaceIndexes[2]);
        }
        #endregion

        #region Overridden Methods
        /// <summary>
        /// Loads a node set from a file or resource and addes them to the set of predefined nodes.
        /// </summary>
        protected override NodeStateCollection LoadPredefinedNodes(ISystemContext context)
        {
            NodeStateCollection predefinedNodes = new NodeStateCollection();
            predefinedNodes.LoadFromBinaryResource(context,
                "Quickstarts.Boiler.Server.Opc.Ua.MTConnect.PredefinedNodes.uanodes",
                typeof(BoilerNodeManager).GetTypeInfo().Assembly,
                true);
            predefinedNodes.LoadFromBinaryResource(context,
                "Quickstarts.Boiler.Server.Quickstarts.Boiler.PredefinedNodes.uanodes",
                typeof(BoilerNodeManager).GetTypeInfo().Assembly,
                true);
            return predefinedNodes;
        }
        #endregion

        #region INodeManager Members
        /// <summary>
        /// Does any initialization required before the address space can be used.
        /// </summary>
        /// <remarks>
        /// The externalReferences is an out parameter that allows the node manager to link to nodes
        /// in other node managers. For example, the 'Objects' node is managed by the CoreNodeManager and
        /// should have a reference to the root folder node(s) exposed by this node manager.  
        /// </remarks>
        public override void CreateAddressSpace(IDictionary<NodeId, IList<IReference>> externalReferences)
        {
            lock (Lock)
            {
                LoadPredefinedNodes(SystemContext, externalReferences);

                // find the untyped Boiler1 node that was created when the model was loaded.
                BaseObjectState passiveNode = (BaseObjectState)FindPredefinedNode(new NodeId(Objects.Boiler1, NamespaceIndexes[0]), typeof(BaseObjectState));

                
                // Passive node for Memex_3
                BaseObjectState passiveNode2 = (BaseObjectState)FindPredefinedNode(new NodeId(Opc.Ua.MTConnect.Objects.Memex_3Axis, NamespaceIndexes[2]), typeof(BaseObjectState));
                // convert the untyped node to a typed node that can be manipulated within the server.
                Memex_3 = new CuttingToolState(null);
                Memex_3.Create(SystemContext, passiveNode2);
                Memex_3.EventNotifier = EventNotifiers.SubscribeToEvents;
                // replaces the untyped predefined nodes with their strongly typed versions.
                AddPredefinedNode(SystemContext, Memex_3);
                
                /*
                // Passive node for Mazak01
                BaseObjectState passiveNode2 = (BaseObjectState)FindPredefinedNode(new NodeId(Opc.Ua.MTConnect.Objects.Mazak01, NamespaceIndexes[2]), typeof(BaseObjectState));
                // convert the untyped node to a typed node that can be manipulated within the server.
                Mazak01 = new CuttingToolState(null);
                Mazak01.Create(SystemContext, passiveNode2);
                // replaces the untyped predefined nodes with their strongly typed versions.
                AddPredefinedNode(SystemContext, Mazak01);
                */


                // convert the untyped node to a typed node that can be manipulated within the server.
                m_boiler1 = new BoilerState(null);
                m_boiler1.Create(SystemContext, passiveNode);
                m_boiler2 = new BoilerState(null);
                
                // replaces the untyped predefined nodes with their strongly typed versions.
                AddPredefinedNode(SystemContext, m_boiler1);

                // initialize it from the type model and assign unique node ids.
                m_boiler2.Create(
                   SystemContext,
                   null,
                   new QualifiedName("Boiler #2", NamespaceIndexes[1]),
                   null,
                   true);

                // link root to objects folder.
                IList<IReference> references = null;

                if (!externalReferences.TryGetValue(Opc.Ua.ObjectIds.ObjectsFolder, out references))
                {
                    externalReferences[Opc.Ua.ObjectIds.ObjectsFolder] = references = new List<IReference>();
                }
                references.Add(new NodeStateReference(Opc.Ua.ReferenceTypeIds.Organizes, false, m_boiler2.NodeId));
                /*
                references.Add(new NodeStateReference(Opc.Ua.ReferenceTypeIds.Organizes, false, m_Door1.NodeId));
                references.Add(new NodeStateReference(Opc.Ua.ReferenceTypeIds.Organizes, false, m_cutter1.NodeId));
                references.Add(new NodeStateReference(Opc.Ua.ReferenceTypeIds.Organizes, false, m_Mazak01.NodeId));
                */

                // store it and all of its children in the pre-defined nodes dictionary for easy look up.
                AddPredefinedNode(SystemContext, m_boiler2);
               
                // start a simulation that changes the values of the nodes.
                
                m_simulationTimer = new Timer(DoSimulation, null, 1000, 1000);
            }
        }

        /// <summary>
        /// Frees any resources allocated for the address space.
        /// </summary>
        public override void DeleteAddressSpace()
        {
            lock (Lock)
            {
                base.DeleteAddressSpace();
            }
        }

        /// <summary>
        /// Returns a unique handle for the node.
        /// </summary>
        protected override NodeHandle GetManagerHandle(ServerSystemContext context, NodeId nodeId, IDictionary<NodeId, NodeState> cache)
        {
            lock (Lock)
            {
                // quickly exclude nodes that are not in the namespace.
                if (!IsNodeIdInNamespace(nodeId))
                {
                    return null;
                }

                // check for predefined nodes.
                if (PredefinedNodes != null)
                {
                    NodeState node = null;

                    if (PredefinedNodes.TryGetValue(nodeId, out node))
                    {
                        NodeHandle handle = new NodeHandle();

                        handle.NodeId = nodeId;
                        handle.Validated = true;
                        handle.Node = node;

                        return handle;
                    }
                }

                return null;
            }
        }

        /// <summary>
        /// Verifies that the specified node exists.
        /// </summary>
        protected override NodeState ValidateNode(
            ServerSystemContext context,
            NodeHandle handle,
            IDictionary<NodeId, NodeState> cache)
        {
            // not valid if no root.
            if (handle == null)
            {
                return null;
            }

            // check if previously validated.
            if (handle.Validated)
            {
                return handle.Node;
            }

            // TBD

            return null;
        }
        #endregion

        #region Overridden Methods
        /// <summary>
        /// Does the simulation and streaming.
        /// </summary>
        /// <param name="state">The state.</param>
        private void DoSimulation(object state)
        {
            try
            {
                /// This region conducts a simulation for basic parts
                #region
                double value1 = m_boiler1.Drum.LevelIndicator.Output.Value;
                value1 = ((int)(value1 + 10)) % 100;
                m_boiler1.Drum.LevelIndicator.Output.Value = value1;
                m_boiler1.ClearChangeMasks(SystemContext, true);

                #endregion

            }
            catch (Exception e)
            {
                Utils.Trace(e, "Unexpected error during simulation.");
            }

            /// ****** This region streams data from an XML file to the server ******
            /// --- Note that this is device specific ---
            /// Set the file path of where the data located. Include the 
            /// Ex: C:\Users\DataFiles
            string filepath = @"X:\Work\OPC\UA-.NETStandard\SampleApplications\Workshop\Boiler\Sample DataFiles";
            string[] readText;
            double value;
            int lengthArray;
            
            #region /// Manual Streaming via Text File ///

            #region /// Streaming for Memex_3 Device ///
            
            /// This streams values to the X tag
            try
            {
                readText = File.ReadAllLines(filepath + "/Data_Memex-3Axis_Xact_ACTUAL_position.txt");
                value = Memex_3.Axes.X.Value;
                lengthArray = readText.Length;
                value = Convert.ToDouble(readText[lengthArray - 1]);
            }
            catch { value = Memex_3.Axes.X.Value; }
            Memex_3.Axes.X.Value = value;
            Memex_3.ClearChangeMasks(SystemContext, true);

            /// This streams values to the Y tag
            try
            {
                readText = File.ReadAllLines(filepath + "/Data_Memex-3Axis_Yact_ACTUAL_position.txt");
                value = Memex_3.Axes.Y.Value;
                lengthArray = readText.Length;
                value = Convert.ToDouble(readText[lengthArray - 1]);
            }
            catch { value = Memex_3.Axes.Y.Value; }
            Memex_3.Axes.Y.Value = value;
            Memex_3.ClearChangeMasks(SystemContext, true);

            /// This streams values to the X tag
            try
            {
                readText = File.ReadAllLines(filepath + "/Data_Memex-3Axis_Zact_ACTUAL_position.txt");
                value = Memex_3.Axes.Z.Value;
                lengthArray = readText.Length;
                value = Convert.ToDouble(readText[lengthArray - 1]);
            }
            catch { value = Memex_3.Axes.Z.Value; }
            Memex_3.Axes.Z.Value = value;
            Memex_3.ClearChangeMasks(SystemContext, true);

            /// This streams the Emergency Stop value
            EmergencyStopTypeEnum Test;
            string readTextString;
            try
            {
                readTextString = File.ReadAllText(filepath + "/EmergencyStop.txt");
                value = Convert.ToInt32(readTextString);
                Test = (EmergencyStopTypeEnum)value;
            }
            catch { Test = Memex_3.Controller.EmergencyStop.Value; }
            
            
            Memex_3.Controller.EmergencyStop.Value = Test;
            Memex_3.ClearChangeMasks(SystemContext, true);

            /// This streams the value of Message
            try
            {
                readTextString = File.ReadAllText(filepath + "/Message.txt");
                Memex_3.Controller.Message.Value = readTextString;
            }
            catch
            {
                readTextString = Memex_3.Controller.Message.Value;
                Memex_3.Controller.Message.Value = readTextString;
            }

            /// This streams the value of line
            ushort readTextInt;
            try
            {
                readTextString = File.ReadAllText(filepath + "/Line.txt");
                readTextInt = Convert.ToUInt16(readTextString);
                readTextInt = (ushort)readTextInt;
                Memex_3.Controller.Line.Value = readTextInt;
            }
            catch
            {
                readTextInt = Memex_3.Controller.Line.Value;
                Memex_3.Controller.Line.Value = readTextInt;
            }

            /// This streams the value of MTCurrentState
            try
            {
                readTextString = File.ReadAllText(filepath + "/MTCurrentState.txt");
                Memex_3.Axes.XLoad.MTCurrentState.Value = readTextString;
            }
            catch
            {
                readTextString = Memex_3.Axes.XLoad.MTCurrentState.Value;
                Memex_3.Axes.XLoad.MTCurrentState.Value = readTextString;
            }
            
            #endregion

            #region /// Streaming for Mazak01 Device ///
            /*
            /// This streams values to the X tag
            try
            {
                readText = File.ReadAllLines(@"C:\Users\rdf1\Documents\codes\Python_Files\DataFiles\Data_Mazak01_Xabs_ACTUAL_position.txt");
                value = Mazak01.Axes.X.Value;
                lengthArray = readText.Length;
                value = Convert.ToDouble(readText[lengthArray - 1]);
            }
            catch { value = Mazak01.Axes.X.Value; }
            Mazak01.Axes.X.Value = value;
            Mazak01.ClearChangeMasks(SystemContext, true);

            /// This streams values to the Y tag
            try
            {
                readText = File.ReadAllLines(@"C:\Users\rdf1\Documents\codes\Python_Files\DataFiles\Data_Mazak01_Yabs_ACTUAL_position.txt");
                value = Mazak01.Axes.Y.Value;
                lengthArray = readText.Length;

                value = Convert.ToDouble(readText[lengthArray - 1]);
            }
            catch { value = Mazak01.Axes.Y.Value; }
            Mazak01.Axes.Y.Value = value;
            Mazak01.ClearChangeMasks(SystemContext, true);

            /// This streams values to the X tag
            try
            {
                readText = File.ReadAllLines(@"C:\Users\rdf1\Documents\codes\Python_Files\DataFiles\Data_Mazak01_Zabs_ACTUAL_position.txt");
                value = Mazak01.Axes.Z.Value;
                lengthArray = readText.Length;

                value = Convert.ToDouble(readText[lengthArray - 1]);
            }
            catch { value = Mazak01.Axes.Z.Value; }
            Mazak01.Axes.Z.Value = value;
            Mazak01.ClearChangeMasks(SystemContext, true);
            */ 
            #endregion


            #endregion

            #region /// Streaming via XML (not working currently)
            /// <summary
            /// This area of code does not currently work
            /// </summary>
            /*
            XNamespace aw = "{urn:mtconnect.org:MTConnectStreams:1.3}";
            XElement xmlTree = XElement.Load("http://simulator.memexoee.com/current", LoadOptions.PreserveWhitespace );
            try {
                
                IEnumerable<XElement> de = from el in xmlTree.Descendants("Samples") select el;
                foreach (XElement el in de)
                    Console.WriteLine(el.Name);
                System.Diagnostics.Debug.WriteLine("MADE IT!\n");
            }
            catch (Exception e) { Utils.Trace(e, "Unexpected error during simulation."); System.Diagnostics.Debug.WriteLine("Error: ", e); }
                 
            //XElement xmlTree = XElement.Parse(booksFromFile);
            //System.Diagnostics.Debug.WriteLine(booksFromFile);
            //System.Diagnostics.Debug.WriteLine("xmltree", xmlTree);
            */
            #endregion
        }
        #endregion

        #region Private Fields
        private BoilerServerConfiguration m_configuration;
        private BoilerState m_boiler1;
        private BoilerState m_boiler2;
        ///private MTDoorState m_Door1;
        private uint m_nodeIdCounter;
        private Timer m_simulationTimer;
        private CuttingToolState m_cutter1;
        private CuttingToolState Mazak01;
        private CuttingToolState Memex_3;


        #endregion
    }
}

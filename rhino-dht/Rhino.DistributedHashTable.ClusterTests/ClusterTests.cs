using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Rhino.DistributedHashTable.Client;
using Rhino.DistributedHashTable.Exceptions;
using Rhino.DistributedHashTable.Hosting;
using Rhino.DistributedHashTable.Internal;
using Rhino.DistributedHashTable.Parameters;
using Rhino.PersistentHashTable;
using Xunit;

namespace Rhino.DistributedHashTable.ClusterTests
{
    public class ClusterTests
    {
        // we have to do this ugliness because the cluster is in a state of flux right now
        // with segments moving & topology changes
        public static void RepeatWhileThereAreTopologyChangedErrors(Action action)
        {
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    action();
                    return;
                }
                catch (TopologyVersionDoesNotMatchException)
                {
                    Thread.Sleep(250);
                }
            }
            throw new InvalidOperationException(
                "Could not execute action because we got too many TopologyVersionDoesNotMatchException");
        }

        #region Nested type: JoiningToCluster

        public class JoiningToCluster : FullIntegrationTest, IDisposable
        {
            private readonly DistributedHashTableMasterHost masterHost;
            private readonly Uri masterUri = new Uri("rhino.dht://" + Environment.MachineName + ":2200/master");
            private readonly DistributedHashTableStorageHost storageHostA;
            private readonly DistributedHashTableStorageHost storageHostB;

            public JoiningToCluster()
            {
                masterHost = new DistributedHashTableMasterHost();
                storageHostA = new DistributedHashTableStorageHost(masterUri);
                storageHostB = new DistributedHashTableStorageHost(masterUri, "nodeB", 2203);
                masterHost.Start();
                storageHostA.Start();
            }

            #region IDisposable Members

            public void Dispose()
            {
                storageHostB.Dispose();
                storageHostA.Dispose();
                masterHost.Dispose();
            }

            #endregion

            [Fact]
            public void AfterBothNodesJoinedWillAutomaticallyReplicateToBackupNode()
            {
                storageHostB.Start();

                var masterProxy = new DistributedHashTableMasterClient(masterUri);

                Topology topology;
                for (int i = 0; i < 50; i++)
                {
                    topology = masterProxy.GetTopology();
                    int count = topology.Segments
                        .Where(x => x.AssignedEndpoint == storageHostA.Endpoint)
                        .Count();

                    if (count == 4096)
                        break;
                    Thread.Sleep(500);
                }

                topology = masterProxy.GetTopology();
                int segment = topology.Segments.First(x => x.AssignedEndpoint == storageHostA.Endpoint).Index;
                RepeatWhileThereAreTopologyChangedErrors(() =>
                {
                    using (var nodeA = new DistributedHashTableStorageClient(storageHostA.Endpoint))
                    {
                        nodeA.Put(topology.Version, new ExtendedPutRequest
                        {
                            Bytes = new byte[] {2, 2, 0, 0},
                            Key = "abc",
                            Segment = segment
                        });
                    }
                });

                RepeatWhileThereAreTopologyChangedErrors(() =>
                {
                    using (var nodeB = new DistributedHashTableStorageClient(storageHostB.Endpoint))
                    {
                        topology = masterProxy.GetTopology();
                        Value[][] values = null;
                        for (int i = 0; i < 100; i++)
                        {
                            values = nodeB.Get(topology.Version, new ExtendedGetRequest
                            {
                                Key = "abc",
                                Segment = segment
                            });
                            if (values[0].Length != 0)
                                break;
                            Thread.Sleep(250);
                        }
                        Assert.Equal(new byte[] {2, 2, 0, 0}, values[0][0].Data);
                    }
                });
            }

            [Fact]
            public void CanReadValueFromBackupNodeThatUsedToBeTheSegmentOwner()
            {
                storageHostB.Start();

                var masterProxy = new DistributedHashTableMasterClient(masterUri);

                Topology topology;
                for (int i = 0; i < 50; i++)
                {
                    topology = masterProxy.GetTopology();
                    int count = topology.Segments
                        .Where(x => x.AssignedEndpoint == storageHostA.Endpoint)
                        .Count();

                    if (count == 4096)
                        break;
                    Thread.Sleep(500);
                }

                int segment = 0;

                RepeatWhileThereAreTopologyChangedErrors(() =>
                {
                    topology = masterProxy.GetTopology();
                    segment = topology.Segments.First(x => x.AssignedEndpoint == storageHostA.Endpoint).Index;
                    using (var nodeA = new DistributedHashTableStorageClient(storageHostA.Endpoint))
                    {
                        nodeA.Put(topology.Version, new ExtendedPutRequest
                        {
                            Bytes = new byte[] {2, 2, 0, 0},
                            Key = "abc",
                            Segment = segment
                        });
                    }
                });

                RepeatWhileThereAreTopologyChangedErrors(() =>
                {
                    using (var nodeB = new DistributedHashTableStorageClient(storageHostB.Endpoint))
                    {
                        topology = masterProxy.GetTopology();
                        Value[][] values = null;
                        for (int i = 0; i < 100; i++)
                        {
                            values = nodeB.Get(topology.Version, new ExtendedGetRequest
                            {
                                Key = "abc",
                                Segment = segment
                            });
                            if (values[0].Length != 0)
                                break;
                            Thread.Sleep(250);
                        }
                        Assert.Equal(new byte[] {2, 2, 0, 0}, values[0][0].Data);
                    }
                });

                using (var nodeA = new DistributedHashTableStorageClient(storageHostA.Endpoint))
                {
                    topology = masterProxy.GetTopology();
                    Value[][] values = nodeA.Get(topology.Version, new ExtendedGetRequest
                    {
                        Key = "abc",
                        Segment = segment
                    });
                    Assert.Equal(new byte[] {2, 2, 0, 0}, values[0][0].Data);
                }
            }


            [Fact]
            public void TwoNodesCanJoinToTheCluster()
            {
                storageHostB.Start();

                int countOfSegmentsInA = 0;
                int countOfSegmentsInB = 0;
                var masterProxy = new DistributedHashTableMasterClient(masterUri);

                for (int i = 0; i < 50; i++)
                {
                    Topology topology = masterProxy.GetTopology();
                    Dictionary<NodeEndpoint, int> results = topology.Segments.GroupBy(x => x.AssignedEndpoint)
                        .Select(x => new {x.Key, Count = x.Count()})
                        .ToDictionary(x => x.Key, x => x.Count);

                    results.TryGetValue(storageHostA.Endpoint, out countOfSegmentsInA);
                    results.TryGetValue(storageHostB.Endpoint, out countOfSegmentsInB);
                    if (countOfSegmentsInA == countOfSegmentsInB &&
                        countOfSegmentsInB == 4096)
                        return;
                    Thread.Sleep(500);
                }
                Assert.True(false,
                            "Should have found two nodes sharing responsability for the geometry: " + countOfSegmentsInA +
                            " - " +
                            countOfSegmentsInB);
            }

            [Fact]
            public void AfterTwoNodesJoinTheClusterEachSegmentHasBackup()
            {
                storageHostB.Start();

                var masterProxy = new DistributedHashTableMasterClient(masterUri);

                Topology topology;
                for (int i = 0; i < 50; i++)
                {
                    topology = masterProxy.GetTopology();
                    bool allSegmentsHaveBackups = topology.Segments.All(x => x.Backups.Count > 0);

                    if (allSegmentsHaveBackups)
                        break;
                    Thread.Sleep(500);
                }
                topology = masterProxy.GetTopology();
                Assert.True(
                    topology.Segments.All(x => x.Backups.Count > 0)
                    );
            }

            [Fact]
            public void WillReplicateValuesToSecondJoin()
            {
                var masterProxy = new DistributedHashTableMasterClient(masterUri);
                using (var nodeA = new DistributedHashTableStorageClient(storageHostA.Endpoint))
                {
                    Topology topology = masterProxy.GetTopology();
                    nodeA.Put(topology.Version, new ExtendedPutRequest
                    {
                        Bytes = new byte[] {2, 2, 0, 0},
                        Key = "abc",
                        Segment = 1
                    });
                }

                storageHostB.Start(); //will replicate all odd segments here now

                for (int i = 0; i < 500; i++)
                {
                    Topology topology = masterProxy.GetTopology();
                    if (topology.Segments[1].AssignedEndpoint ==
                        storageHostB.Endpoint)
                        break;
                    Thread.Sleep(500);
                }


                Value[][] values = null;
                RepeatWhileThereAreTopologyChangedErrors(() =>
                {
                    using (var nodeB = new DistributedHashTableStorageClient(storageHostB.Endpoint))
                    {
                        Topology topology = masterProxy.GetTopology();
                        values = nodeB.Get(topology.Version, new ExtendedGetRequest
                        {
                            Key = "abc",
                            Segment = 1
                        });
                    }
                });
                Assert.Equal(new byte[] {2, 2, 0, 0}, values[0][0].Data);
            }
        }

        #endregion
    }
}
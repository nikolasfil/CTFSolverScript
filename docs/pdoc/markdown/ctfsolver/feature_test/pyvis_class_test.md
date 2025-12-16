Module ctfsolver.feature_test.pyvis_class_test
==============================================

Classes
-------

`GraphVisualizer(height='750px', width='100%', bgcolor='#222222', font_color='white')`
:   

    ### Methods

    `add_edge(self, source, target, **kwargs)`
    :

    `add_graph_data(self, graph_dict)`
    :   Add a dictionary like:
        {
            "A": ["B", "C"],
            "B": ["D"],
        }

    `add_node(self, node_id, label=None, **kwargs)`
    :

    `show(self, filename='graph.html')`
    :
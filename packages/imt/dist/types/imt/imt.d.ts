import { IMTHashFunction, IMTMerkleProof, IMTNode } from "./types";
/**
 * An {@link IMT} (aka Incremental Merkle Tree) is a type of data structure used in cryptography and
 * computer science for efficiently verifying the integrity of a large set of data,
 * especially in situations where new data is added over time. It is based on the concept
 * of a Merkle tree, and its key feature is its ability to efficiently update the tree
 * when new data is added or existing data is modified.
 * In this implementation, the tree is constructed using a fixed {@link IMT#depth}
 * value, and a list of {@link IMT#zeroes} (one for each level) is used to compute the
 * hash of a node when not all of its children are defined. The number of children for each
 * node can also be specified with the {@link IMT#arity} parameter.
 */
export default class IMT {
    /**
     * The matrix where all the tree nodes are stored. The first index indicates
     * the level of the tree, while the second index represents the node's
     * position within that specific level.
     */
    private readonly _nodes;
    /**
     * A list of zero values calculated during the initialization of the tree.
     * The list contains one value for each level of the tree, and the value for
     * a given level is equal to the hash of the previous level's value.
     * The first value is the zero hash provided by the user.
     * These values are used to calculate the hash of a node in case some of its
     * children are missing.
     */
    private readonly _zeroes;
    /**
     * The hash function used to compute the tree nodes.
     */
    private readonly _hash;
    /**
     * The depth of the tree, which is the number of edges from the node to the
     * tree's root node.
     */
    private readonly _depth;
    /**
     * The number of children per node.
     */
    private readonly _arity;
    /**
     * It initializes the tree with an hash function, the depth, the zero value to use for zeroes
     * and the arity (i.e. the number of children for each node). It also takes an optional parameter
     * to initialize the tree with a list of leaves.
     * @param hash The hash function used to create nodes.
     * @param depth The tree depth.
     * @param zeroValue The zero value used to create zeroes.
     * @param arity The number of children for each node.
     * @param leaves The list of initial leaves.
     */
    constructor(hash: IMTHashFunction, depth: number, zeroValue: IMTNode, arity?: number, leaves?: IMTNode[]);
    /**
     * The root of the tree. This value doesn't need to be stored as
     * it is always the first and unique element of the last level of the tree.
     * Its value can be retrieved in {@link IMT#_nodes}.
     * @returns The root hash of the tree.
     */
    get root(): IMTNode;
    /**
     * The depth of the tree, which equals the number of levels - 1.
     * @returns The depth of the tree.
     */
    get depth(): number;
    /**
     * The leaves of the tree. They can be retrieved from the first
     * level of the tree using {@link IMT#_nodes}. The returned
     * value is a copy of the array and not the original object.
     * @returns The list of tree leaves.
     */
    get leaves(): IMTNode[];
    /**
     * The whole tree.
     * @returns The whole tree.
     */
    get nodes(): IMTNode[][];
    /**
     * The list of zero values calculated during the initialization of the tree.
     * @returns The list of pre-computed zeroes.
     */
    get zeroes(): IMTNode[];
    /**
     * The number of children per node.
     * @returns The number of children per node.
     */
    get arity(): number;
    /**
     * It returns the index of a leaf. If the leaf does not exist it returns -1.
     * @param leaf A leaf of the tree.
     * @returns The index of the leaf.
     */
    indexOf(leaf: IMTNode): number;
    /**
     * The leaves are inserted incrementally. If 'i' is the index of the last
     * leaf, the new one will be inserted at position 'i + 1'. Every time a
     * new leaf is inserted, the nodes that separate the new leaf from the root
     * of the tree are created or updated if they already exist, from bottom to top.
     * When a node has only one child (the left one), its value is the hash of that
     * node and the zero value of that level. Otherwise, the hash of the children
     * is calculated.
     * @param leaf The new leaf to be inserted in the tree.
     */
    insert(leaf: IMTNode): void;
    /**
     * It deletes a leaf from the tree. It does not remove the leaf from
     * the data structure, but rather it sets the leaf to be deleted to the zero value.
     * @param index The index of the leaf to be deleted.
     */
    delete(index: number): void;
    /**
     * It updates a leaf in the tree. It's very similar to the {@link IMT#insert} function.
     * @param index The index of the leaf to be updated.
     * @param newLeaf The new leaf to be inserted.
     */
    update(index: number, newLeaf: IMTNode): void;
    /**
     * It creates a {@link IMTMerkleProof} for a leaf of the tree.
     * That proof can be verified by this tree using the same hash function.
     * @param index The index of the leaf for which a Merkle proof will be generated.
     * @returns The Merkle proof of the leaf.
     */
    createProof(index: number): IMTMerkleProof;
    /**
     * It verifies a {@link IMTMerkleProof} to confirm that a leaf indeed
     * belongs to the tree.
     * @param proof The Merkle tree proof.
     * @returns True if the leaf is part of the tree, and false otherwise.
     */
    verifyProof(proof: IMTMerkleProof): boolean;
}

/**
 * @module @zk-kit/imt
 * @version 2.0.0-beta.1
 * @file Incremental Merkle tree implementations in TypeScript.
 * @copyright Ethereum Foundation 2024
 * @license MIT
 * @see [Github]{@link https://github.com/privacy-scaling-explorations/zk-kit/tree/main/packages/imt}
*/
'use strict';

function checkParameter(value, name, ...types) {
    if (value === undefined) {
        throw new TypeError(`Parameter '${name}' is not defined`);
    }
    if (!types.includes(typeof value)) {
        throw new TypeError(`Parameter '${name}' is none of these types: ${types.join(", ")}`);
    }
}

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
class IMT {
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
    constructor(hash, depth, zeroValue, arity = 2, leaves = []) {
        var _a;
        checkParameter(hash, "hash", "function");
        checkParameter(depth, "depth", "number");
        checkParameter(zeroValue, "zeroValue", "number", "string", "bigint");
        checkParameter(arity, "arity", "number");
        checkParameter(leaves, "leaves", "object");
        if (leaves.length > Math.pow(arity, depth)) {
            throw new Error(`The tree cannot contain more than ${Math.pow(arity, depth)} leaves`);
        }
        // Initialize the attributes.
        this._hash = hash;
        this._depth = depth;
        this._zeroes = [];
        this._nodes = [];
        this._arity = arity;
        for (let level = 0; level < depth; level += 1) {
            this._zeroes.push(zeroValue);
            this._nodes[level] = [];
            // There must be a zero value for each tree level (except the root).
            zeroValue = hash(Array(this._arity).fill(zeroValue));
        }
        this._nodes[depth] = [];
        // It initializes the tree with a list of leaves if there are any.
        if (leaves.length > 0) {
            this._nodes[0] = leaves;
            for (let level = 0; level < depth; level += 1) {
                for (let index = 0; index < Math.ceil(this._nodes[level].length / arity); index += 1) {
                    const position = index * arity;
                    const children = [];
                    for (let i = 0; i < arity; i += 1) {
                        children.push((_a = this._nodes[level][position + i]) !== null && _a !== void 0 ? _a : this.zeroes[level]);
                    }
                    this._nodes[level + 1][index] = hash(children);
                }
            }
        }
        else {
            // If there are no leaves, the default root is the last zero value.
            this._nodes[depth][0] = zeroValue;
        }
        // Freeze the array objects. It prevents unintentional changes.
        Object.freeze(this._zeroes);
        Object.freeze(this._nodes);
    }
    setNodes(nodes) {
        this._nodes = nodes;
    }
    /**
     * The root of the tree. This value doesn't need to be stored as
     * it is always the first and unique element of the last level of the tree.
     * Its value can be retrieved in {@link IMT#_nodes}.
     * @returns The root hash of the tree.
     */
    get root() {
        return this._nodes[this.depth][0];
    }
    /**
     * The depth of the tree, which equals the number of levels - 1.
     * @returns The depth of the tree.
     */
    get depth() {
        return this._depth;
    }
    /**
     * The leaves of the tree. They can be retrieved from the first
     * level of the tree using {@link IMT#_nodes}. The returned
     * value is a copy of the array and not the original object.
     * @returns The list of tree leaves.
     */
    get leaves() {
        return this._nodes[0].slice();
    }
    /**
     * The whole tree.
     * @returns The whole tree.
     */
    get nodes() {
        return this._nodes;
    }
    /**
     * The list of zero values calculated during the initialization of the tree.
     * @returns The list of pre-computed zeroes.
     */
    get zeroes() {
        return this._zeroes;
    }
    /**
     * The number of children per node.
     * @returns The number of children per node.
     */
    get arity() {
        return this._arity;
    }
    /**
     * It returns the index of a leaf. If the leaf does not exist it returns -1.
     * @param leaf A leaf of the tree.
     * @returns The index of the leaf.
     */
    indexOf(leaf) {
        checkParameter(leaf, "leaf", "number", "string", "bigint");
        return this._nodes[0].indexOf(leaf);
    }
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
    insert(leaf) {
        checkParameter(leaf, "leaf", "number", "string", "bigint");
        if (this._nodes[0].length >= Math.pow(this.arity, this.depth)) {
            throw new Error("The tree is full");
        }
        let node = leaf;
        let index = this._nodes[0].length;
        for (let level = 0; level < this.depth; level += 1) {
            const position = index % this.arity;
            const levelStartIndex = index - position;
            const levelEndIndex = levelStartIndex + this.arity;
            const children = [];
            this._nodes[level][index] = node;
            for (let i = levelStartIndex; i < levelEndIndex; i += 1) {
                if (i < this._nodes[level].length) {
                    children.push(this._nodes[level][i]);
                }
                else {
                    children.push(this._zeroes[level]);
                }
            }
            node = this._hash(children);
            index = Math.floor(index / this.arity);
        }
        this._nodes[this.depth][0] = node;
    }
    /**
     * It deletes a leaf from the tree. It does not remove the leaf from
     * the data structure, but rather it sets the leaf to be deleted to the zero value.
     * @param index The index of the leaf to be deleted.
     */
    delete(index) {
        this.update(index, this.zeroes[0]);
    }
    /**
     * It updates a leaf in the tree. It's very similar to the {@link IMT#insert} function.
     * @param index The index of the leaf to be updated.
     * @param newLeaf The new leaf to be inserted.
     */
    update(index, newLeaf) {
        checkParameter(index, "index", "number");
        if (index < 0 || index >= this._nodes[0].length) {
            throw new Error("The leaf does not exist in this tree");
        }
        let node = newLeaf;
        for (let level = 0; level < this.depth; level += 1) {
            const position = index % this.arity;
            const levelStartIndex = index - position;
            const levelEndIndex = levelStartIndex + this.arity;
            const children = [];
            this._nodes[level][index] = node;
            for (let i = levelStartIndex; i < levelEndIndex; i += 1) {
                if (i < this._nodes[level].length) {
                    children.push(this._nodes[level][i]);
                }
                else {
                    children.push(this.zeroes[level]);
                }
            }
            node = this._hash(children);
            index = Math.floor(index / this.arity);
        }
        this._nodes[this.depth][0] = node;
    }
    /**
     * It creates a {@link IMTMerkleProof} for a leaf of the tree.
     * That proof can be verified by this tree using the same hash function.
     * @param index The index of the leaf for which a Merkle proof will be generated.
     * @returns The Merkle proof of the leaf.
     */
    createProof(index) {
        checkParameter(index, "index", "number");
        if (index < 0 || index >= this._nodes[0].length) {
            throw new Error("The leaf does not exist in this tree");
        }
        const siblings = [];
        const pathIndices = [];
        const leafIndex = index;
        for (let level = 0; level < this.depth; level += 1) {
            const position = index % this.arity;
            const levelStartIndex = index - position;
            const levelEndIndex = levelStartIndex + this.arity;
            pathIndices[level] = position;
            siblings[level] = [];
            for (let i = levelStartIndex; i < levelEndIndex; i += 1) {
                if (i !== index) {
                    if (i < this._nodes[level].length) {
                        siblings[level].push(this._nodes[level][i]);
                    }
                    else {
                        siblings[level].push(this.zeroes[level]);
                    }
                }
            }
            index = Math.floor(index / this.arity);
        }
        return { root: this.root, leaf: this._nodes[0][leafIndex], pathIndices, siblings, leafIndex };
    }
    /**
     * It verifies a {@link IMTMerkleProof} to confirm that a leaf indeed
     * belongs to the tree.
     * @param proof The Merkle tree proof.
     * @returns True if the leaf is part of the tree, and false otherwise.
     */
    verifyProof(proof) {
        checkParameter(proof, "proof", "object");
        checkParameter(proof.root, "proof.root", "number", "string", "bigint");
        checkParameter(proof.leaf, "proof.leaf", "number", "string", "bigint");
        checkParameter(proof.siblings, "proof.siblings", "object");
        checkParameter(proof.pathIndices, "proof.pathElements", "object");
        let node = proof.leaf;
        for (let i = 0; i < proof.siblings.length; i += 1) {
            const children = proof.siblings[i].slice();
            children.splice(proof.pathIndices[i], 0, node);
            node = this._hash(children);
        }
        return proof.root === node;
    }
}

/**
 * It throws a type error if the parameter value has not been defined.
 * @param parameterValue The parameter value.
 * @param parameterName The parameter name.
 */
function requireDefinedParameter(parameterValue, parameterName) {
    if (typeof parameterValue === "undefined") {
        throw new TypeError(`Parameter '${parameterName}' is not defined`);
    }
}
/**
 * It throws a type error if the parameter value is not a number.
 * @param parameterValue The parameter value.
 * @param parameterName The parameter name.
 */
function requireNumber(parameterValue, parameterName) {
    if (typeof parameterValue !== "number") {
        throw new TypeError(`Parameter '${parameterName}' is not a number`);
    }
}
/**
 * It throws a type error if the parameter value is not a string.
 * @param parameterValue The parameter value.
 * @param parameterName The parameter name.
 */
function requireString(parameterValue, parameterName) {
    if (typeof parameterValue !== "string") {
        throw new TypeError(`Parameter '${parameterName}' is not a string`);
    }
}
/**
 * It throws a type error if the parameter value is not a function.
 * @param parameterValue The parameter value.
 * @param parameterName The parameter name.
 */
function requireFunction(parameterValue, parameterName) {
    if (typeof parameterValue !== "function") {
        throw new TypeError(`Parameter '${parameterName}' is not a function`);
    }
}
/**
 * It throws a type error if the parameter value is not an array.
 * @param parameterValue The parameter value.
 * @param parameterName The parameter name.
 */
function requireArray(parameterValue, parameterName) {
    if (typeof parameterValue !== "object" && !Array.isArray(parameterValue)) {
        throw new TypeError(`Parameter '${parameterName}' is not an array`);
    }
}

/**
 * The {@link LeanIMT} is an optimized binary version of the {@link IMT}.
 * This implementation exclusively supports binary trees, eliminates the use of
 * zeroes, and the tree's {@link LeanIMT#depth} is dynamic. When a node doesn't have the right child,
 * instead of using a zero hash as in the IMT, the node's value becomes that
 * of its left child. Furthermore, rather than utilizing a static tree depth,
 * it is updated based on the number of {@link LeanIMT#leaves} in the tree. This approach
 * results in the calculation of significantly fewer hashes, making the tree more efficient.
 */
class LeanIMT {
    /**
     * It initializes the tree with a given hash function and an optional list of leaves.
     * @param hash The hash function used to create nodes.
     * @param leaves The list of leaves.
     */
    constructor(hash, leaves = []) {
        requireDefinedParameter(hash, "hash");
        requireFunction(hash, "hash");
        requireArray(leaves, "leaves");
        // Initialize the attributes.
        this._nodes = [[]];
        this._hash = hash;
        // Initialize the tree with a list of leaves if there are any.
        if (leaves.length > 0) {
            this.insertMany(leaves);
        }
    }
    /**
     * The root of the tree. This value doesn't need to be stored as
     * it is always the first and unique element of the last level of the tree.
     * Its value can be retrieved in {@link LeanIMT#_nodes}.
     * @returns The root hash of the tree.
     */
    get root() {
        return this._nodes[this.depth][0];
    }
    /**
     * The depth of the tree, which equals the number of levels - 1.
     * @returns The depth of the tree.
     */
    get depth() {
        return this._nodes.length - 1;
    }
    /**
     * The leaves of the tree. They can be retrieved from the first
     * level of the tree using {@link LeanIMT#_nodes}. The returned
     * value is a copy of the array and not the original object.
     * @returns The list of tree leaves.
     */
    get leaves() {
        return this._nodes[0].slice();
    }
    /**
     * The size of the tree, which the number of its leaves.
     * It's the length of the first level's list.
     * @returns The number of leaves of the tree.
     */
    get size() {
        return this._nodes[0].length;
    }
    /**
     * It returns the index of a leaf. If the leaf does not exist it returns -1.
     * @param leaf A leaf of the tree.
     * @returns The index of the leaf.
     */
    indexOf(leaf) {
        requireDefinedParameter(leaf, "leaf");
        return this._nodes[0].indexOf(leaf);
    }
    /**
     * It returns true if the leaf exists, and false otherwise
     * @param leaf A leaf of the tree.
     * @returns True if the tree has the leaf, and false otherwise.
     */
    has(leaf) {
        requireDefinedParameter(leaf, "leaf");
        return this._nodes[0].includes(leaf);
    }
    /**
     * The leaves are inserted incrementally. If 'i' is the index of the last
     * leaf, the new one will be inserted at position 'i + 1'. Every time a
     * new leaf is inserted, the nodes that separate the new leaf from the root
     * of the tree are created or updated if they already exist, from bottom to top.
     * When a node has only one child (the left one), its value takes on the value
     * of the child. Otherwise, the hash of the children is calculated.
     * @param leaf The new leaf to be inserted in the tree.
     */
    insert(leaf) {
        requireDefinedParameter(leaf, "leaf");
        // If the next depth is greater, a new tree level will be added.
        if (this.depth < Math.ceil(Math.log2(this.size + 1))) {
            // Adding an array is like adding a new level.
            this._nodes.push([]);
        }
        let node = leaf;
        // The index of the new leaf equals the number of leaves in the tree.
        let index = this.size;
        for (let level = 0; level < this.depth; level += 1) {
            this._nodes[level][index] = node;
            // Bitwise AND, 0 -> left or 1 -> right.
            // If the node is a right node the parent node will be the hash
            // of the child nodes. Otherwise, parent will equal left child node.
            if (index & 1) {
                const sibling = this._nodes[level][index - 1];
                node = this._hash(sibling, node);
            }
            // Right shift, it divides a number by 2 and discards the remainder.
            index >>= 1;
        }
        // Store the new root.
        this._nodes[this.depth] = [node];
    }
    /**
     * This function is useful when you want to insert N leaves all at once.
     * It is more efficient than using the {@link LeanIMT#insert} method N times because it
     * significantly reduces the number of cases where a node has only one
     * child, which is a common occurrence in gradual insertion.
     * @param leaves The list of leaves to be inserted.
     */
    insertMany(leaves) {
        requireDefinedParameter(leaves, "leaves");
        requireArray(leaves, "leaves");
        if (leaves.length === 0) {
            throw new Error("There are no leaves to add");
        }
        let startIndex = this.size >> 1;
        this._nodes[0].push(...leaves);
        // Calculate how many tree levels will need to be added
        // using the number of leaves.
        const numberOfNewLevels = Math.ceil(Math.log2(this.size)) - this.depth;
        // Add the new levels.
        for (let i = 0; i < numberOfNewLevels; i += 1) {
            this._nodes.push([]);
        }
        for (let level = 0; level < this.depth; level += 1) {
            // Calculate the number of nodes of the next level.
            const numberOfNodes = Math.ceil(this._nodes[level].length / 2);
            for (let index = startIndex; index < numberOfNodes; index += 1) {
                const rightNode = this._nodes[level][index * 2 + 1];
                const leftNode = this._nodes[level][index * 2];
                const parentNode = rightNode ? this._hash(leftNode, rightNode) : leftNode;
                this._nodes[level + 1][index] = parentNode;
            }
            startIndex >>= 1;
        }
    }
    /**
     * It updates a leaf in the tree. It's very similar to the {@link LeanIMT#insert} function.
     * @param index The index of the leaf to be updated.
     * @param newLeaf The new leaf to be inserted.
     */
    update(index, newLeaf) {
        requireDefinedParameter(index, "index");
        requireDefinedParameter(newLeaf, "newLeaf");
        requireNumber(index, "index");
        let node = newLeaf;
        for (let level = 0; level < this.depth; level += 1) {
            this._nodes[level][index] = node;
            if (index & 1) {
                const sibling = this._nodes[level][index - 1];
                node = this._hash(sibling, node);
            }
            else {
                // In this case there could still be a right node
                // because the path might not be the rightmost one
                // (like the 'insert' function).
                const sibling = this._nodes[level][index + 1];
                if (sibling) {
                    node = this._hash(node, sibling);
                }
            }
            index >>= 1;
        }
        this._nodes[this.depth] = [node];
    }
    /**
     * It generates a {@link LeanIMTMerkleProof} for a leaf of the tree.
     * That proof can be verified by this tree using the same hash function.
     * @param index The index of the leaf for which a Merkle proof will be generated.
     * @returns The Merkle proof of the leaf.
     */
    generateProof(index) {
        requireDefinedParameter(index, "index");
        requireNumber(index, "index");
        if (index < 0 || index >= this.size) {
            throw new Error(`The leaf at index '${index}' does not exist in this tree`);
        }
        const leaf = this.leaves[index];
        const siblings = [];
        const path = [];
        for (let level = 0; level < this.depth; level += 1) {
            const isRightNode = index & 1;
            const siblingIndex = isRightNode ? index - 1 : index + 1;
            const sibling = this._nodes[level][siblingIndex];
            // If the sibling node does not exist, it means that the node at
            // this level has the same value as its child. Therefore, there
            // is no need to include it in the proof since there is no hash to calculate.
            if (sibling !== undefined) {
                path.push(isRightNode);
                siblings.push(sibling);
            }
            index >>= 1;
        }
        // The index might be different from the original index of the leaf, since
        // in some cases some siblings are not included (as explained above).
        return { root: this.root, leaf, index: Number.parseInt(path.reverse().join(""), 2), siblings };
    }
    /**
     * It verifies a {@link LeanIMTMerkleProof} to confirm that a leaf indeed
     * belongs to the tree.
     * @param proof The Merkle tree proof.
     * @returns True if the leaf is part of the tree, and false otherwise.
     */
    verifyProof(proof) {
        requireDefinedParameter(proof, "proof");
        const { root, leaf, siblings, index } = proof;
        requireDefinedParameter(proof.root, "proof.root");
        requireDefinedParameter(proof.leaf, "proof.leaf");
        requireDefinedParameter(proof.siblings, "proof.siblings");
        requireDefinedParameter(proof.index, "proof.index");
        requireArray(proof.siblings, "proof.siblings");
        requireNumber(proof.index, "proof.index");
        let node = leaf;
        for (let i = 0; i < siblings.length; i += 1) {
            if ((index >> i) & 1) {
                node = this._hash(siblings[i], node);
            }
            else {
                node = this._hash(node, siblings[i]);
            }
        }
        return root === node;
    }
    /**
     * It enables the conversion of the full tree structure into a JSON string,
     * facilitating future imports of the tree. This approach is beneficial for
     * large trees, as it saves time by storing hashes instead of recomputing them
     * @returns The stringified JSON of the tree.
     */
    export() {
        return JSON.stringify(this._nodes, (_, v) => (typeof v === "bigint" ? v.toString() : v));
    }
    /**
     * It imports an entire tree by initializing the nodes without calculating
     * any hashes. Note that it is crucial to ensure the integrity of the tree
     * before or after importing it.
     * The tree must be empty before importing.
     * @param nodes The stringified JSON of the tree.
     */
    import(nodes) {
        requireDefinedParameter(nodes, "nodes");
        requireString(nodes, "nodes");
        if (this.size !== 0) {
            throw new Error("Import failed: the target tree structure is not empty");
        }
        this._nodes = JSON.parse(nodes);
    }
}

exports.IMT = IMT;
exports.LeanIMT = LeanIMT;

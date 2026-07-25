package org.crbf.domain.model.artifact;

import java.util.List;

public record DependencyPath(List<Artifact> path) {

    public DependencyPath {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("The dependency path cannot be null or empty.");
        }
        path = List.copyOf(path);
    }

    public Artifact root() {
        return path.get(0);
    }

    public Artifact target() {
        return path.get(path.size() - 1);
    }

    /**
     * Returns the number of edges in the path.
     * A direct dependency has depth 1 (root -> target).
     * A transitive dependency has depth > 1.
     */
    public int depth() {
        return path.size() - 1;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < path.size(); i++) {
            sb.append(path.get(i).gav());
            if (i < path.size() - 1) {
                sb.append(" -> ");
            }
        }
        return sb.toString();
    }
}
package org.crbf.application.port.out;

import java.nio.file.Path;
import java.util.List;

import org.crbf.application.model.vex.VexFinding;

public interface ExportVexPort {
    public void exportVex(List<VexFinding> findings, Path outputDirectory);
}

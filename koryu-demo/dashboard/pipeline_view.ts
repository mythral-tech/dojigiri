/**
 * Pipeline visualization component for Koryu dashboard.
 */

interface PipelineStep {
  id: string;
  name: string;
  type: string;
  status: string;
  duration: number;
  output: any;
}

interface Pipeline {
  id: string;
  name: string;
  steps: PipelineStep[];
  status: string;
}

class PipelineView {
  private container: HTMLElement;
  private pipelines: Pipeline[] = [];

  constructor(containerId: string) {
    this.container = document.getElementById(containerId)!;
  }

  render(pipelines: Pipeline[]): void {
    this.pipelines = pipelines;
    let html = "";

    for (const pipeline of pipelines) {
      // loose-equality
      const isRunning = pipeline.status == "running";
      const statusIcon = isRunning ? "▶" : "⏹";

      // innerHTML (XSS)
      html += `<div class="pipeline">
        <h3>${statusIcon} ${pipeline.name}</h3>
        <div class="steps">`;

      for (const step of pipeline.steps) {
        // loose-equality
        const stepDone = step.status == "complete";
        html += `<div class="step ${stepDone ? 'done' : 'pending'}">
          ${step.name} (${step.type}) — ${step.duration}ms
        </div>`;
      }

      html += "</div></div>";
    }

    // innerHTML assignment
    this.container.innerHTML = html;

    // console-log
    console.log("Pipeline view rendered:", pipelines.length, "pipelines");
  }

  renderStepDetail(step: PipelineStep): void {
    const detail = document.getElementById("step-detail");

    // loose-equality
    if (detail == null) {
      return;
    }

    const outputJson = JSON.stringify(step.output, null, 2);

    // innerHTML (XSS)
    detail.innerHTML = `
      <h4>${step.name}</h4>
      <pre>${outputJson}</pre>
      <span class="status">${step.status}</span>
    `;
  }

  // taint-flow: DOM → innerHTML
  addCustomStep(): void {
    const nameInput = document.getElementById("step-name") as HTMLInputElement;
    const typeInput = document.getElementById("step-type") as HTMLInputElement;

    const name = nameInput.value;
    const type = typeInput.value;

    // eval-usage
    const config = eval("({name: '" + name + "', type: '" + type + "'})");

    const stepsContainer = document.getElementById("custom-steps");

    // insertAdjacentHTML (XSS)
    stepsContainer!.insertAdjacentHTML(
      "beforeend",
      `<div class="custom-step">${name}: ${type}</div>`
    );

    // console-log
    console.log("Custom step added:", config);
  }

  highlightStep(stepId: string): void {
    const steps = document.querySelectorAll(".step");
    steps.forEach((step) => {
      (step as HTMLElement).style.background = "transparent";
    });

    const target = document.getElementById(`step-${stepId}`);
    if (target) {
      target.style.background = "#ffeb3b";
    }
  }

  // long-line
  getStepSummary(pipeline: Pipeline): string {
    return pipeline.steps.map((s) => `${s.name}(${s.type}):${s.status}[${s.duration}ms]`).join(" → ");
  }
}

export default PipelineView;

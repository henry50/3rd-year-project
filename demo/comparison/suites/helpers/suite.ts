import { Suite } from "benchmark";
import { suite as bennySuite, complete, configure, cycle, save } from "benny";
import {
    CaseResult,
    CaseResultWithDiff,
    Config,
    SaveOptions,
    Summary,
} from "benny/src/internal/common-types";
import kleur from "kleur";

const options = {
    cases: {
        // setting min and max time to -Infinity forces benchmark.js
        // to run each test minSamples times
        minTime: -Infinity,
        maxTime: -Infinity,
        minSamples: 100,
    },
};

function saveFileName(summary: Summary): string {
    const d = summary.date;
    const pad = (n: number) => String(n < 10 ? "0" + n : n);
    const date = [d.getFullYear(), d.getMonth(), d.getDate()].map(pad).join("-");
    const time = [d.getHours(), d.getMinutes(), d.getSeconds()].map(pad).join("-");
    return [summary.name.replace(/\s+/g, "_").toLowerCase(), date, time].join("_");
}

const saveOptions: SaveOptions = {
    file: saveFileName,
    folder: "results",
}

// These types and the getStatus and meanCycle functions
// are modified from benny/src/suite.ts
type PartialMethod = (config: Config) => Promise<(suiteObj: Suite) => Suite>;

type SuiteFn = (name: string, ...fns: PartialMethod[]) => Promise<Summary>;

type CycleFn = (result: CaseResult, summary: Summary) => any;

type GetStatus = (
    item: CaseResultWithDiff,
    index: number,
    summary: Summary,
    ops: string,
    fastestOps: string,
) => string;

const getStatus: GetStatus = (item, index, summary, ops, fastestOps) => {
    const isFastest = index === summary.fastest.index;
    const isSlowest = index === summary.slowest.index;
    const statusShift = fastestOps.length - ops.length + 2;

    return (
        " ".repeat(statusShift) +
        (isFastest
            ? kleur.green("| fastest")
            : isSlowest
              ? kleur.red(`| slowest, ${item.percentSlower}% slower`)
              : kleur.yellow(`| ${item.percentSlower}% slower`))
    );
};

const meanCycle: CycleFn = (_, summary) => {
    const allCompleted = summary.results.every((item) => item.samples > 0);
    const fastestOps = summary.results[summary.fastest.index].ops.toString();

    const progress = Math.round(
        (summary.results.filter((result) => result.samples !== 0).length /
            summary.results.length) *
            100,
    );

    const progressInfo = `Progress: ${progress}%`;

    const output = summary.results
        .map((item, index) => {
            const ops = item.ops.toString();
            const mean = (item.details.mean * 1000).toFixed(2);
            const margin = item.margin.toFixed(2);

            return item.samples
                ? kleur.cyan(`\n  ${item.name}:\n`) +
                      `    Average ${mean} ms, ±${margin}% ${
                          allCompleted
                              ? getStatus(item, index, summary, ops, fastestOps)
                              : ""
                      }`
                : null;
        })
        .filter((item) => item !== null)
        .join("\n");

    return `${progressInfo}\n${output}`;
};

/**
 * Customised benchmark suite
 * @param name Suite name
 * @param entries Suite tests
 * @returns Promise resolving to a summary of results
 */
const suite: SuiteFn = async (name, ...entries) => {
    return bennySuite(
        name,
        ...entries,
        cycle(meanCycle),
        complete(),
        configure(options),
        save(saveOptions)
    );
};

export default suite;

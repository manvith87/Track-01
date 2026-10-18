import { Link } from "react-router-dom";
import { EmptyState, SectionCard } from "../components/StateViews";

export function NotFoundPage() {
  return (
    <div className="mx-auto max-w-2xl">
      <SectionCard title="Not found" description="This route is not part of the BlastRadius workspace.">
        <EmptyState
          title="Nothing here"
          description="The requested screen does not exist. Start from the repository screen or open an analysis from its findings screen."
          action={
            <Link
              to="/"
              className="focus-ring inline-flex rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-100 hover:bg-zinc-800"
            >
              Go to repository analysis
            </Link>
          }
        />
      </SectionCard>
    </div>
  );
}

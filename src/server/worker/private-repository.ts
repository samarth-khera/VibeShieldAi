/**
 * Workflow/claim value used instead of the URL for private repositories, so the repository name
 * never appears in public workflow inputs. The worker gets the source from the signed source endpoint.
 */
export const PRIVATE_REPOSITORY = "private";

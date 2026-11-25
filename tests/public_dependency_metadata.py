"""Hosted read-only token capability smoke over fixed PUBLIC upstream metadata."""
import os

from secure_release import project_dependency_review as review


def main():
    # The workflow supplies its existing contents:read token to this trusted
    # step only. Never discover or print another credential or private identity.
    token = os.environ.get('BUILDER_READ_TOKEN')
    if not token:
        raise ValueError('public metadata smoke requires existing read credential')
    commit = '11bd71901bbe5b1630ceea73d27597364c9af683'
    with review.github_metadata_credentials(token):
        if review.public_commit('actions/checkout', 'v4.2.2') != commit:
            raise ValueError('public metadata smoke tag identity mismatch')
        review.action_version('actions/checkout', commit)
        transferred = '6ab9eb1bda2574c4ddb79809fc9247783eaf9021'
        if review.public_commit('mymindstorm/setup-emsdk', 'v14') != transferred:
            raise ValueError('public metadata smoke transferred tag identity mismatch')
        review.action_version('mymindstorm/setup-emsdk', transferred)
    print('PUBLIC_DEPENDENCY_METADATA_AUTH_SUCCESS')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Even an unexpected networking exception cannot stringify request URLs,
        # headers or credentials into the public synthetic workflow console.
        raise SystemExit('PUBLIC_DEPENDENCY_METADATA_AUTH_FAILED') from None

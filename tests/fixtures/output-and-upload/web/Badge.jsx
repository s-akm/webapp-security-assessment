export const New = () => <b dangerouslySetInnerHTML={{ __html: "<i>new</i>" }} />;
export const Post = ({ post }) => <div dangerouslySetInnerHTML={{ __html: post.html }} />;
